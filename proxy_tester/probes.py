"""Low-level proxy probes: raw HTTP, SOCKS tunnels, and the optional VIES check."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import ssl
import time
from collections.abc import Sequence
from contextlib import suppress
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .constants import (
    PROBE_DEADLINE_GRACE,
    STRICT_IP_TIMEOUT_CAP,
    USER_AGENT,
    VIES_API_ACCEPT,
    VIES_CHECK_VAT_URL,
    VIES_RESPONSE_BODY_LIMIT,
    WRITER_CLOSE_TIMEOUT,
)
from .models import ProbeTarget, ProxyCandidate, format_host
from .parsing import looks_like_ip_block, normalize_vies_probe_vat, vies_vat_is_valid_response


def build_tls_context(verify_tls: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def seconds_left(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def probe_deadline(timeout_s: float) -> float:
    return time.monotonic() + max(0.35, timeout_s + PROBE_DEADLINE_GRACE)


def ip_check_deadline(timeout_s: float) -> float:
    """Strict IP validation gets its own short budget after reachability passes."""
    return time.monotonic() + max(0.5, min(timeout_s + PROBE_DEADLINE_GRACE, STRICT_IP_TIMEOUT_CAP))


def candidate_hard_timeout(args) -> float:
    """One hard ceiling per candidate so a late worker can never hang the run."""
    rounds = max(1, int(getattr(args, "stability_checks", 1)))
    reachability_budget = rounds * max(0.35, float(args.timeout) + PROBE_DEADLINE_GRACE)
    ip_budget = 0.0
    if getattr(args, "require_different_ip", False):
        ip_budget = max(0.5, min(float(args.timeout) + PROBE_DEADLINE_GRACE, STRICT_IP_TIMEOUT_CAP))
    return max(0.8, reachability_budget + ip_budget + 0.25)


def expected_probe_status(split) -> Optional[int]:
    """/generate_204 endpoints answer 204; everything else takes any 2xx/3xx."""
    if (split.path or "").rstrip("/") == "/generate_204":
        return 204
    return None


def build_probe_targets(urls: Sequence[str]) -> List[ProbeTarget]:
    """Parse probe URLs once, up front, so workers never re-parse them."""
    targets: List[ProbeTarget] = []
    for raw_url in urls:
        split = urlsplit(raw_url)
        scheme = split.scheme.lower()
        host = split.hostname
        if scheme not in {"http", "https"} or not host:
            raise ValueError(f"Unsupported probe URL: {raw_url}")
        port = split.port or (443 if scheme == "https" else 80)
        path_qs = split.path or "/"
        if split.query:
            path_qs += "?" + split.query
        targets.append(
            ProbeTarget(
                raw_url=raw_url,
                scheme=scheme,
                host=host,
                port=port,
                path_qs=path_qs,
                expected_status=expected_probe_status(split),
            )
        )
    return targets


def http_proxy_target_url(target: ProbeTarget) -> str:
    """Absolute-form URL, as required in the request line to a plain HTTP proxy."""
    default_port = 443 if target.scheme == "https" else 80
    port = "" if target.port == default_port else f":{target.port}"
    return f"{target.scheme}://{format_host(target.host)}{port}{target.path_qs}"


def proxy_auth_header(candidate: ProxyCandidate) -> str:
    if candidate.username is None:
        return ""
    password = candidate.password or ""
    raw = f"{candidate.username}:{password}".encode("utf-8", errors="ignore")
    token = base64.b64encode(raw).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"


def response_status_ok(target: ProbeTarget, status: Optional[int]) -> bool:
    if status is None:
        return False
    if target.expected_status is not None:
        return status == target.expected_status
    return 200 <= status < 400


async def close_writer(writer) -> None:
    """Close a stream writer quietly across all supported Python versions."""
    if writer is None:
        return
    with suppress(Exception):
        writer.close()
    wait_closed = getattr(writer, "wait_closed", None)
    if wait_closed is not None:
        with suppress(Exception, asyncio.TimeoutError):
            await asyncio.wait_for(wait_closed(), timeout=WRITER_CLOSE_TIMEOUT)


async def read_http_response(reader, deadline: float, body_limit: int = 0) -> Tuple[Optional[int], str]:
    """Read a status line, skip headers, and optionally take a small body."""
    try:
        remaining = seconds_left(deadline)
        if remaining <= 0:
            return None, ""
        status_line = await asyncio.wait_for(reader.readline(), timeout=remaining)
    except Exception:
        return None, ""
    if not status_line:
        return None, ""

    parts = status_line.split(None, 2)
    if len(parts) < 2:
        return None, ""
    try:
        status = int(parts[1])
    except Exception:
        return None, ""

    while True:
        try:
            remaining = seconds_left(deadline)
            if remaining <= 0:
                return status, ""
            header_line = await asyncio.wait_for(reader.readline(), timeout=remaining)
        except Exception:
            return status, ""
        if not header_line or header_line in {b"\r\n", b"\n"}:
            break

    if body_limit <= 0:
        return status, ""

    try:
        remaining = min(seconds_left(deadline), 1.0)
        if remaining <= 0:
            return status, ""
        body = await asyncio.wait_for(reader.read(body_limit), timeout=remaining)
    except Exception:
        body = b""
    return status, body.decode("utf-8", errors="ignore")


async def read_http_response_full(
    reader,
    deadline: float,
    body_limit: int = VIES_RESPONSE_BODY_LIMIT,
) -> Tuple[Optional[int], Dict[str, str], str]:
    """Read a small response including chunked bodies, as the VIES API returns."""
    try:
        remaining = seconds_left(deadline)
        if remaining <= 0:
            return None, {}, ""
        status_line = await asyncio.wait_for(reader.readline(), timeout=remaining)
    except Exception:
        return None, {}, ""
    if not status_line:
        return None, {}, ""

    parts = status_line.split(None, 2)
    if len(parts) < 2:
        return None, {}, ""
    try:
        status = int(parts[1])
    except Exception:
        return None, {}, ""

    headers: Dict[str, str] = {}
    while True:
        try:
            remaining = seconds_left(deadline)
            if remaining <= 0:
                return status, headers, ""
            line = await asyncio.wait_for(reader.readline(), timeout=remaining)
        except Exception:
            return status, headers, ""
        if not line or line in {b"\r\n", b"\n"}:
            break
        text = line.decode("iso-8859-1", errors="ignore")
        if ":" in text:
            name, value = text.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    body = b""
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    content_length = headers.get("content-length")

    try:
        if "chunked" in transfer_encoding:
            while len(body) < body_limit:
                remaining = seconds_left(deadline)
                if remaining <= 0:
                    break
                size_line = await asyncio.wait_for(reader.readline(), timeout=remaining)
                if not size_line:
                    break
                size_text = size_line.split(b";", 1)[0].strip()
                try:
                    size = int(size_text, 16)
                except ValueError:
                    break
                if size <= 0:
                    while True:
                        trailer = await asyncio.wait_for(
                            reader.readline(), timeout=max(0.05, seconds_left(deadline))
                        )
                        if not trailer or trailer in {b"\r\n", b"\n"}:
                            break
                    break
                read_size = min(size, body_limit - len(body))
                if read_size > 0:
                    body += await asyncio.wait_for(
                        reader.readexactly(read_size), timeout=seconds_left(deadline)
                    )
                if size > read_size:
                    await asyncio.wait_for(
                        reader.readexactly(size - read_size), timeout=seconds_left(deadline)
                    )
                with suppress(Exception):
                    await asyncio.wait_for(reader.readexactly(2), timeout=max(0.05, seconds_left(deadline)))
        elif content_length is not None:
            length = max(0, min(int(content_length), body_limit))
            if length:
                body = await asyncio.wait_for(reader.readexactly(length), timeout=seconds_left(deadline))
        elif body_limit > 0:
            body = await asyncio.wait_for(
                reader.read(body_limit), timeout=min(1.5, max(0.05, seconds_left(deadline)))
            )
    except Exception:
        pass

    return status, headers, body.decode("utf-8", errors="ignore")


async def request_via_plain_http_proxy(
    candidate: ProxyCandidate,
    target: ProbeTarget,
    deadline: float,
    body_limit: int = 0,
) -> Tuple[bool, Optional[str]]:
    """HTTP proxy + HTTP target: one absolute-form request, no tunnel needed."""
    writer = None
    try:
        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False, None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(candidate.host, candidate.port), timeout=remaining
        )

        request = (
            f"GET {http_proxy_target_url(target)} HTTP/1.1\r\n"
            f"Host: {target.host}\r\n"
            f"{proxy_auth_header(candidate)}"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        writer.write(request)

        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False, None
        await asyncio.wait_for(writer.drain(), timeout=remaining)

        status, body = await read_http_response(reader, deadline, body_limit=body_limit)
        if not response_status_ok(target, status):
            return False, None
        return True, body
    except Exception:
        return False, None
    finally:
        await close_writer(writer)


async def request_via_proxy(
    AsyncProxy,
    candidate: ProxyCandidate,
    target: ProbeTarget,
    deadline: float,
    tls_context: ssl.SSLContext,
    body_limit: int = 0,
) -> Tuple[bool, Optional[str]]:
    """Send one small request through the proxy, tunnelling when required."""
    sock = None
    writer = None

    if candidate.scheme == "http" and target.scheme == "http":
        return await request_via_plain_http_proxy(
            candidate=candidate, target=target, deadline=deadline, body_limit=body_limit
        )

    try:
        proxy = AsyncProxy.from_url(candidate.proxy_url)
        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False, None
        sock = await proxy.connect(dest_host=target.host, dest_port=target.port, timeout=remaining)

        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False, None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=None,
                port=None,
                sock=sock,
                ssl=tls_context if target.scheme == "https" else None,
                server_hostname=target.host if target.scheme == "https" else None,
            ),
            timeout=remaining,
        )

        request = (
            f"GET {target.path_qs} HTTP/1.1\r\n"
            f"Host: {target.host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        writer.write(request)

        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False, None
        await asyncio.wait_for(writer.drain(), timeout=remaining)

        status, body = await read_http_response(reader, deadline, body_limit=body_limit)
        if not response_status_ok(target, status):
            return False, None
        return True, body
    except Exception:
        return False, None
    finally:
        await close_writer(writer)
        if writer is None and sock is not None:
            with suppress(Exception):
                sock.close()


async def probe_reachability(
    AsyncProxy,
    candidate: ProxyCandidate,
    targets: Sequence[ProbeTarget],
    tls_context: ssl.SSLContext,
    timeout_s: float,
) -> bool:
    """Race several tiny endpoints and succeed on the first one that answers."""
    deadline = probe_deadline(timeout_s)

    # The Windows Proactor loop emits overlapped-cancel noise when many pending
    # probe tasks are cancelled at once, so probe sequentially there instead.
    if os.name == "nt":
        for target in targets:
            if seconds_left(deadline) <= 0:
                break
            ok, _ = await request_via_proxy(
                AsyncProxy=AsyncProxy,
                candidate=candidate,
                target=target,
                deadline=deadline,
                tls_context=tls_context,
                body_limit=0,
            )
            if ok:
                return True
        return False

    tasks = {
        asyncio.create_task(
            request_via_proxy(
                AsyncProxy=AsyncProxy,
                candidate=candidate,
                target=target,
                deadline=deadline,
                tls_context=tls_context,
                body_limit=0,
            )
        )
        for target in targets
    }

    try:
        pending = set(tasks)
        while pending:
            remaining = seconds_left(deadline)
            if remaining <= 0:
                break
            done, pending = await asyncio.wait(
                pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                break
            for task in done:
                ok, _ = task.result()
                if ok:
                    for other in pending:
                        other.cancel()
                    if pending:
                        with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                            await asyncio.wait_for(
                                asyncio.gather(*pending, return_exceptions=True), timeout=0.3
                            )
                    return True
        return False
    finally:
        leftovers = [task for task in tasks if not task.done()]
        for task in leftovers:
            task.cancel()
        if leftovers:
            with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(asyncio.gather(*leftovers, return_exceptions=True), timeout=0.3)


def build_vies_probe_request(vat_id: str) -> Tuple[str, int, str, bytes]:
    """Pre-render the VIES POST so workers only pay for the network round trip."""
    country, number = normalize_vies_probe_vat(vat_id)
    target = urlsplit(VIES_CHECK_VAT_URL)
    if target.scheme != "https" or not target.hostname:
        raise ValueError(f"Unsupported VIES URL: {VIES_CHECK_VAT_URL}")
    path_qs = target.path or "/"
    if target.query:
        path_qs += "?" + target.query
    payload = json.dumps({"countryCode": country, "vatNumber": number}, separators=(",", ":")).encode("utf-8")
    request = (
        f"POST {path_qs} HTTP/1.1\r\n"
        f"Host: {target.hostname}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Accept: {VIES_API_ACCEPT}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore") + payload
    return target.hostname, int(target.port or 443), f"{country}{number}", request


async def probe_vies_vat_via_proxy(
    AsyncProxy,
    candidate: ProxyCandidate,
    tls_context: ssl.SSLContext,
    timeout_s: float,
    vat_id: str,
) -> bool:
    """Opt-in deep check: the proxy must complete a real VIES VAT validation."""
    deadline = probe_deadline(timeout_s)
    sock = None
    writer = None

    try:
        host, port, normalized_vat, request = build_vies_probe_request(vat_id)

        proxy = AsyncProxy.from_url(candidate.proxy_url)
        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False
        sock = await proxy.connect(dest_host=host, dest_port=port, timeout=remaining)

        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=None, port=None, sock=sock, ssl=tls_context, server_hostname=host),
            timeout=remaining,
        )

        writer.write(request)
        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False
        await asyncio.wait_for(writer.drain(), timeout=remaining)

        status, _, body = await read_http_response_full(reader, deadline, body_limit=VIES_RESPONSE_BODY_LIMIT)
        if status in {403, 429} or looks_like_ip_block(body):
            return False
        if status != 200 or not body:
            return False

        country, number = normalize_vies_probe_vat(normalized_vat)
        return vies_vat_is_valid_response(body, country, number)
    except Exception:
        return False
    finally:
        await close_writer(writer)
        if writer is None and sock is not None:
            with suppress(Exception):
                sock.close()
