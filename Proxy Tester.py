#!/usr/bin/env python3
"""
Fetch public proxies from multiple GitHub-based sources, validate them from the
current machine, discover their actual protocol when needed, and save working
results split by protocol.

Requirements:
    pip install "requests[socks]"

Examples:
    python proxy_tester_rewritten.py
    python proxy_tester_rewritten.py --workers 120 --limit 5000
    python proxy_tester_rewritten.py --target-url https://ec.europa.eu/taxation_customs/vies/
    python proxy_tester_rewritten.py --skip-target-check --allow-multi-scheme
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote, urlsplit

try:
    import requests
except Exception as exc:  # pragma: no cover - handled at runtime
    raise SystemExit(
        "Missing dependency: requests. Install it with: pip install \"requests[socks]\""
    ) from exc

try:
    import socks  # type: ignore  # noqa: F401
    HAS_PYSOCKS = True
except Exception:
    HAS_PYSOCKS = False


USER_AGENT = "proxy-tester/2.0"
PROTOCOLS: Tuple[str, ...] = ("http", "socks4", "socks5")
DEFAULT_TARGET_URLS: Tuple[str, ...] = (
    "https://ec.europa.eu/taxation_customs/vies/",
)
DEFAULT_PROBE_URLS: Tuple[str, ...] = (
    "http://httpbin.org/ip",
    "https://api.ipify.org?format=json",
    "https://httpbin.org/ip",
)
DEFAULT_IP_ECHO_URLS: Tuple[str, ...] = (
    "https://api.ipify.org?format=json",
    "https://httpbin.org/ip",
    "https://ifconfig.me/ip",
)
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$"
)
TOKEN_SPLIT_RE = re.compile(r"[\s,;]+")


@dataclass(frozen=True)
class SourceSpec:
    name: str
    urls: Tuple[str, ...]
    scheme_hint: Optional[str] = None


@dataclass
class ProxyCandidate:
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    sources: Set[str] = field(default_factory=set)
    hints: Set[str] = field(default_factory=set)

    @property
    def endpoint(self) -> str:
        return f"{format_host(self.host)}:{self.port}"

    @property
    def key(self) -> Tuple[str, int, Optional[str], Optional[str]]:
        return (self.host, self.port, self.username, self.password)

    def proxy_url(self, scheme: str) -> str:
        auth = ""
        if self.username is not None:
            auth = quote(self.username, safe="")
            if self.password is not None:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        host = format_host(self.host)
        return f"{scheme}://{auth}{host}:{self.port}"


@dataclass
class SchemeResult:
    scheme: str
    latency_ms: float
    exit_ip: Optional[str]
    ip_changed: Optional[bool]
    working_targets: List[str]


@dataclass
class CandidateResult:
    candidate: ProxyCandidate
    results: List[SchemeResult]


@dataclass
class Settings:
    workers: int
    connect_timeout: float
    read_timeout: float
    retries: int
    protocols: Tuple[str, ...]
    verify_protocol: bool
    allow_multi_scheme: bool
    probe_urls: Tuple[str, ...]
    target_urls: Tuple[str, ...]
    target_mode: str
    skip_target_check: bool
    require_ip_change: bool
    baseline_ip: Optional[str]

    @property
    def request_timeout(self) -> Tuple[float, float]:
        return (self.connect_timeout, self.read_timeout)


BUILTIN_SOURCES: Tuple[SourceSpec, ...] = (
    SourceSpec(
        name="proxifly_http",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
        ),
        scheme_hint="http",
    ),
    SourceSpec(
        name="proxifly_socks4",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
        ),
        scheme_hint="socks4",
    ),
    SourceSpec(
        name="proxifly_socks5",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
        ),
        scheme_hint="socks5",
    ),
    SourceSpec(
        name="monosans_http",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        ),
        scheme_hint="http",
    ),
    SourceSpec(
        name="monosans_socks4",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
    ),
    SourceSpec(
        name="monosans_socks5",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        ),
        scheme_hint="socks5",
    ),
    SourceSpec(
        name="roosterkid_http",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        ),
        scheme_hint="http",
    ),
    SourceSpec(
        name="roosterkid_socks4",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        ),
        scheme_hint="socks4",
    ),
    SourceSpec(
        name="roosterkid_socks5",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        ),
        scheme_hint="socks5",
    ),
    SourceSpec(
        name="speedx_http",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        ),
        scheme_hint="http",
    ),
    SourceSpec(
        name="speedx_socks4",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        ),
        scheme_hint="socks4",
    ),
    SourceSpec(
        name="speedx_socks5",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        ),
        scheme_hint="socks5",
    ),
    SourceSpec(
        name="zaeem_http",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
        ),
        scheme_hint="http",
    ),
    SourceSpec(
        name="zaeem_socks4",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
        ),
        scheme_hint="socks4",
    ),
    SourceSpec(
        name="zaeem_socks5",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
        ),
        scheme_hint="socks5",
    ),
    SourceSpec(
        name="vakhov_http",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/http.txt",
            "https://vakhov.github.io/fresh-proxy-list/https.txt",
        ),
        scheme_hint="http",
    ),
    SourceSpec(
        name="vakhov_socks4",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/socks4.txt",
        ),
        scheme_hint="socks4",
    ),
    SourceSpec(
        name="vakhov_socks5",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/socks5.txt",
        ),
        scheme_hint="socks5",
    ),
    SourceSpec(
        name="clarketm_http",
        urls=(
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        ),
        scheme_hint="http",
    ),
    SourceSpec(
        name="mishakorzik_all",
        urls=(
            "https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/proxy.txt",
            "https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/packages/Proxy.txt",
        ),
        scheme_hint=None,
    ),
)


_thread_local = threading.local()


def fail(message: str, exit_code: int = 2) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def normalize_scheme(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.lower().strip()
    if value == "https":
        return "http"
    if value in PROTOCOLS:
        return value
    return None


def format_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def normalize_host(host: str) -> Optional[str]:
    host = host.strip().strip("[]").strip().lower()
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host if HOSTNAME_RE.fullmatch(host) else None


def valid_port(value: str) -> Optional[int]:
    try:
        port = int(value)
    except Exception:
        return None
    return port if 1 <= port <= 65535 else None


def strip_token(token: str) -> str:
    token = token.strip()
    token = token.strip("\"'`<>(){}")
    token = token.strip(",;")
    if not (token.startswith("[") and "]:" in token):
        token = token.strip("[]")
    token = token.rstrip(".:")
    return token


def parse_host_port(raw: str) -> Optional[Tuple[str, int, Optional[str], Optional[str]]]:
    token = strip_token(raw)
    if not token or token.startswith("#"):
        return None

    username: Optional[str] = None
    password: Optional[str] = None

    if token.startswith("//"):
        token = "http:" + token

    if "://" in token:
        split = urlsplit(token)
        try:
            host = split.hostname
            port = split.port
        except ValueError:
            return None
        if not host or port is None:
            return None
        normalized_host = normalize_host(host)
        if normalized_host is None:
            return None
        return normalized_host, port, split.username, split.password

    host_part = token
    if "@" in token:
        auth_part, host_part = token.rsplit("@", 1)
        if ":" in auth_part:
            username, password = auth_part.split(":", 1)
        else:
            username = auth_part
            password = None

    if host_part.startswith("[") and "]:" in host_part:
        host, port_text = host_part[1:].split("]:", 1)
    else:
        if ":" not in host_part:
            return None
        host, port_text = host_part.rsplit(":", 1)

    port = valid_port(port_text)
    if port is None:
        return None
    normalized_host = normalize_host(host)
    if normalized_host is None:
        return None
    return normalized_host, port, username, password


def parse_proxy_token(raw: str, fallback_scheme: Optional[str]) -> Optional[Tuple[Optional[str], ProxyCandidate]]:
    token = strip_token(raw)
    if not token or token.startswith("#"):
        return None

    scheme_hint = fallback_scheme
    if "://" in token:
        split = urlsplit(token)
        scheme_hint = normalize_scheme(split.scheme) or fallback_scheme

    parsed = parse_host_port(token)
    if parsed is None:
        return None

    host, port, username, password = parsed
    return scheme_hint, ProxyCandidate(host=host, port=port, username=username, password=password)


def parse_proxy_text(text: str, fallback_scheme: Optional[str], max_items: int) -> List[ProxyCandidate]:
    seen: Set[Tuple[str, int, Optional[str], Optional[str]]] = set()
    results: List[ProxyCandidate] = []

    for token in TOKEN_SPLIT_RE.split(text):
        parsed = parse_proxy_token(token, fallback_scheme=fallback_scheme)
        if parsed is None:
            continue
        scheme_hint, candidate = parsed
        if candidate.key in seen:
            continue
        seen.add(candidate.key)
        if scheme_hint:
            candidate.hints.add(scheme_hint)
        results.append(candidate)
        if max_items > 0 and len(results) >= max_items:
            break

    return results


def direct_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def worker_session() -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.trust_env = False
        session.headers.update({"User-Agent": USER_AGENT})
        _thread_local.session = session
    return session


def download_text(urls: Sequence[str], connect_timeout: float, read_timeout: float, retries: int) -> str:
    last_error: Optional[BaseException] = None
    for url in urls:
        for attempt in range(retries):
            try:
                with direct_session() as session:
                    response = session.get(
                        url,
                        timeout=(connect_timeout, read_timeout),
                        allow_redirects=True,
                    )
                    response.raise_for_status()
                    response.encoding = response.encoding or "utf-8"
                    return response.text
            except BaseException as exc:
                last_error = exc
                if attempt + 1 < retries:
                    time.sleep(min(0.3 * (2 ** attempt), 2.0))
    raise RuntimeError(f"all download attempts failed: {last_error}")


def source_catalog() -> Dict[str, SourceSpec]:
    return {source.name: source for source in BUILTIN_SOURCES}


def selected_sources(names: Optional[Sequence[str]]) -> List[SourceSpec]:
    catalog = source_catalog()
    if not names:
        return list(BUILTIN_SOURCES)
    result: List[SourceSpec] = []
    for name in names:
        if name not in catalog:
            fail(f"unknown source '{name}'. Use --list-sources to view valid names.")
        result.append(catalog[name])
    return result


def fetch_candidates(
    sources: Sequence[SourceSpec],
    connect_timeout: float,
    read_timeout: float,
    retries: int,
    max_per_source: int,
    global_limit: int,
    verbose: bool,
) -> Tuple[List[ProxyCandidate], Dict[str, Dict[str, object]]]:
    merged: Dict[Tuple[str, int, Optional[str], Optional[str]], ProxyCandidate] = {}
    stats: Dict[str, Dict[str, object]] = {}

    for source in sources:
        stat: Dict[str, object] = {
            "hint": source.scheme_hint,
            "urls": list(source.urls),
            "downloaded": False,
            "parsed": 0,
            "unique_added": 0,
            "error": None,
        }
        stats[source.name] = stat
        try:
            text = download_text(
                source.urls,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                retries=retries,
            )
            stat["downloaded"] = True
            parsed = parse_proxy_text(text, fallback_scheme=source.scheme_hint, max_items=max_per_source)
            stat["parsed"] = len(parsed)
            added = 0
            for candidate in parsed:
                existing = merged.get(candidate.key)
                if existing is None:
                    existing = ProxyCandidate(
                        host=candidate.host,
                        port=candidate.port,
                        username=candidate.username,
                        password=candidate.password,
                    )
                    merged[candidate.key] = existing
                    added += 1
                existing.sources.add(source.name)
                existing.hints.update(candidate.hints)
                if global_limit > 0 and len(merged) >= global_limit:
                    break
            stat["unique_added"] = added
            if verbose:
                print(
                    f"Fetched {source.name}: parsed={stat['parsed']} unique_added={stat['unique_added']}",
                    file=sys.stderr,
                )
        except BaseException as exc:
            stat["error"] = str(exc)
            if verbose:
                print(f"Failed {source.name}: {exc}", file=sys.stderr)
        if global_limit > 0 and len(merged) >= global_limit:
            break

    return list(merged.values()), stats


def proxy_mapping(scheme: str, candidate: ProxyCandidate) -> Dict[str, str]:
    if scheme == "socks5":
        proxy_url = candidate.proxy_url("socks5h")
    elif scheme == "socks4":
        proxy_url = candidate.proxy_url("socks4a")
    else:
        proxy_url = candidate.proxy_url("http")
    return {"http": proxy_url, "https": proxy_url}


def read_small_text(response: requests.Response, limit: int = 4096) -> str:
    chunks: List[bytes] = []
    size = 0
    try:
        for chunk in response.iter_content(chunk_size=512):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size >= limit:
                break
    finally:
        response.close()
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")


def extract_ip(text: str) -> Optional[str]:
    for token in re.split(r"[^0-9A-Za-z:\.\[\]]+", text):
        token = token.strip().strip("[]")
        if not token:
            continue
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return None


def request_via_proxy(
    session: requests.Session,
    candidate: ProxyCandidate,
    scheme: str,
    url: str,
    timeout: Tuple[float, float],
    need_ip: bool,
) -> Tuple[bool, Optional[float], Optional[str]]:
    started = time.perf_counter()
    response: Optional[requests.Response] = None
    try:
        response = session.get(
            url,
            proxies=proxy_mapping(scheme, candidate),
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
        if response.status_code >= 400:
            response.close()
            return False, None, None
        if need_ip:
            text = read_small_text(response, limit=4096)
            ip_text = extract_ip(text)
            if ip_text is None:
                return False, None, None
            return True, (time.perf_counter() - started) * 1000.0, ip_text

        try:
            next(response.iter_content(chunk_size=256), b"")
        finally:
            response.close()
        return True, (time.perf_counter() - started) * 1000.0, None
    except Exception:
        if response is not None:
            response.close()
        return False, None, None


def protocol_order(candidate: ProxyCandidate, settings: Settings) -> List[str]:
    if not settings.verify_protocol and candidate.hints:
        return [scheme for scheme in settings.protocols if scheme in candidate.hints]

    hinted = [scheme for scheme in settings.protocols if scheme in candidate.hints]
    remaining = [scheme for scheme in settings.protocols if scheme not in candidate.hints]
    return hinted + remaining


def probe_scheme(
    session: requests.Session,
    candidate: ProxyCandidate,
    scheme: str,
    settings: Settings,
) -> Optional[Tuple[float, Optional[str]]]:
    for url in settings.probe_urls:
        ok, latency_ms, exit_ip = request_via_proxy(
            session=session,
            candidate=candidate,
            scheme=scheme,
            url=url,
            timeout=settings.request_timeout,
            need_ip=True,
        )
        if ok and latency_ms is not None:
            return latency_ms, exit_ip
    return None


def target_check(
    session: requests.Session,
    candidate: ProxyCandidate,
    scheme: str,
    settings: Settings,
) -> List[str]:
    if settings.skip_target_check or not settings.target_urls:
        return []

    working: List[str] = []
    for url in settings.target_urls:
        ok, _, _ = request_via_proxy(
            session=session,
            candidate=candidate,
            scheme=scheme,
            url=url,
            timeout=settings.request_timeout,
            need_ip=False,
        )
        if ok:
            working.append(url)
        elif settings.target_mode == "all":
            return []
    if settings.target_mode == "any" and not working:
        return []
    return working


def test_candidate(candidate: ProxyCandidate, settings: Settings) -> CandidateResult:
    session = worker_session()
    results: List[SchemeResult] = []

    for scheme in protocol_order(candidate, settings):
        if scheme != "http" and not HAS_PYSOCKS:
            continue

        probe = probe_scheme(session=session, candidate=candidate, scheme=scheme, settings=settings)
        if probe is None:
            continue
        latency_ms, exit_ip = probe

        ip_changed: Optional[bool] = None
        if settings.baseline_ip and exit_ip:
            ip_changed = exit_ip != settings.baseline_ip
            if settings.require_ip_change and not ip_changed:
                continue

        working_targets = target_check(
            session=session,
            candidate=candidate,
            scheme=scheme,
            settings=settings,
        )
        if not settings.skip_target_check:
            if settings.target_mode == "any" and not working_targets:
                continue
            if settings.target_mode == "all" and len(working_targets) != len(settings.target_urls):
                continue

        results.append(
            SchemeResult(
                scheme=scheme,
                latency_ms=latency_ms,
                exit_ip=exit_ip,
                ip_changed=ip_changed,
                working_targets=working_targets,
            )
        )

        if results and not settings.allow_multi_scheme:
            break

    return CandidateResult(candidate=candidate, results=results)


def detect_public_ip(connect_timeout: float, read_timeout: float) -> Optional[str]:
    with direct_session() as session:
        for url in DEFAULT_IP_ECHO_URLS:
            try:
                response = session.get(url, timeout=(connect_timeout, read_timeout), stream=True)
                if response.status_code >= 400:
                    response.close()
                    continue
                text = read_small_text(response, limit=4096)
                ip_value = extract_ip(text)
                if ip_value:
                    return ip_value
            except Exception:
                continue
    return None


def iter_completed(
    executor: cf.ThreadPoolExecutor,
    candidates: Sequence[ProxyCandidate],
    settings: Settings,
    max_pending: int,
) -> Iterator[CandidateResult]:
    pending: Dict[cf.Future[CandidateResult], ProxyCandidate] = {}
    iterator = iter(candidates)

    while True:
        while len(pending) < max_pending:
            try:
                candidate = next(iterator)
            except StopIteration:
                break
            future = executor.submit(test_candidate, candidate, settings)
            pending[future] = candidate
        if not pending:
            break
        done, _ = cf.wait(pending.keys(), return_when=cf.FIRST_COMPLETED)
        for future in done:
            candidate = pending.pop(future, None)
            try:
                yield future.result()
            except Exception:
                if candidate is not None:
                    yield CandidateResult(candidate=candidate, results=[])


def write_text_list(path: str, items: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for item in items:
            handle.write(item + "\n")


def json_report_rows(results: Sequence[CandidateResult]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for item in results:
        for scheme_result in item.results:
            rows.append(
                {
                    "scheme": scheme_result.scheme,
                    "proxy": item.candidate.proxy_url(scheme_result.scheme),
                    "endpoint": item.candidate.endpoint,
                    "host": item.candidate.host,
                    "port": item.candidate.port,
                    "sources": sorted(item.candidate.sources),
                    "source_hints": sorted(item.candidate.hints),
                    "latency_ms": round(scheme_result.latency_ms, 2),
                    "exit_ip": scheme_result.exit_ip,
                    "ip_changed": scheme_result.ip_changed,
                    "working_targets": scheme_result.working_targets,
                }
            )
    rows.sort(key=lambda row: (row["scheme"], row["latency_ms"], row["proxy"]))
    return rows


def write_reports(
    output_dir: str,
    source_stats: Dict[str, Dict[str, object]],
    candidates: Sequence[ProxyCandidate],
    results: Sequence[CandidateResult],
    settings: Settings,
    started_at: float,
) -> Dict[str, object]:
    os.makedirs(output_dir, exist_ok=True)

    protocol_lists: Dict[str, List[str]] = {scheme: [] for scheme in PROTOCOLS}
    combined: List[str] = []

    for item in results:
        for scheme_result in item.results:
            proxy_url = item.candidate.proxy_url(scheme_result.scheme)
            protocol_lists[scheme_result.scheme].append(proxy_url)
            combined.append(proxy_url)

    for scheme in PROTOCOLS:
        protocol_lists[scheme] = sorted(set(protocol_lists[scheme]))
    combined = sorted(set(combined))

    write_text_list(os.path.join(output_dir, "working_all.txt"), combined)
    for scheme in PROTOCOLS:
        write_text_list(os.path.join(output_dir, f"working_{scheme}.txt"), protocol_lists[scheme])

    report_rows = json_report_rows(results)
    report_path = os.path.join(output_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report_rows, handle, indent=2, ensure_ascii=False)

    summary = {
        "tested_candidates": len(candidates),
        "working_candidates": sum(1 for item in results if item.results),
        "working_by_protocol": {scheme: len(protocol_lists[scheme]) for scheme in PROTOCOLS},
        "baseline_ip": settings.baseline_ip,
        "verify_protocol": settings.verify_protocol,
        "allow_multi_scheme": settings.allow_multi_scheme,
        "target_mode": settings.target_mode,
        "skip_target_check": settings.skip_target_check,
        "require_ip_change": settings.require_ip_change,
        "probe_urls": list(settings.probe_urls),
        "target_urls": list(settings.target_urls),
        "workers": settings.workers,
        "connect_timeout": settings.connect_timeout,
        "read_timeout": settings.read_timeout,
        "elapsed_seconds": round(time.time() - started_at, 2),
        "source_stats": source_stats,
        "outputs": {
            "working_all": os.path.abspath(os.path.join(output_dir, "working_all.txt")),
            "working_http": os.path.abspath(os.path.join(output_dir, "working_http.txt")),
            "working_socks4": os.path.abspath(os.path.join(output_dir, "working_socks4.txt")),
            "working_socks5": os.path.abspath(os.path.join(output_dir, "working_socks5.txt")),
            "report_json": os.path.abspath(report_path),
        },
    }

    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)

    return summary


def default_workers() -> int:
    cpu = os.cpu_count() or 4
    return max(16, min(128, cpu * 16))


def require_socks_if_needed(protocols: Sequence[str]) -> None:
    if any(proto.startswith("socks") for proto in protocols) and not HAS_PYSOCKS:
        fail('Missing dependency for SOCKS support. Install: pip install "requests[socks]"')


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Fetch and validate public proxies on the machine where this script runs."
    )
    ap.add_argument("--output-dir", default="proxy_results", help="Directory for all output files.")
    ap.add_argument(
        "--workers",
        type=int,
        default=default_workers(),
        help=f"Concurrent tests (default: {default_workers()}).",
    )
    ap.add_argument(
        "--connect-timeout",
        type=float,
        default=3.5,
        help="Connect timeout per request in seconds.",
    )
    ap.add_argument(
        "--read-timeout",
        type=float,
        default=4.5,
        help="Read timeout per request in seconds.",
    )
    ap.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries per source download.",
    )
    ap.add_argument(
        "--protocols",
        default="http,socks4,socks5",
        help="Comma-separated protocols to test.",
    )
    ap.add_argument(
        "--probe-url",
        action="append",
        default=[],
        help="Protocol probe URL. Repeat to add more. Default uses lightweight IP-echo URLs.",
    )
    ap.add_argument(
        "--target-url",
        action="append",
        default=[],
        help="Target URL that a proxy must reach. Repeat to add more.",
    )
    ap.add_argument(
        "--target-mode",
        choices=("any", "all"),
        default="any",
        help="Require any or all target URLs to work.",
    )
    ap.add_argument(
        "--skip-target-check",
        action="store_true",
        help="Only classify protocols and skip final target-site validation.",
    )
    ap.add_argument(
        "--require-ip-change",
        action="store_true",
        help="Only keep proxies that change the observed public IP.",
    )
    ap.add_argument(
        "--verify-protocol",
        dest="verify_protocol",
        action="store_true",
        default=True,
        help="Try other protocols if the source hint is wrong.",
    )
    ap.add_argument(
        "--no-verify-protocol",
        dest="verify_protocol",
        action="store_false",
        help="Trust source hints and do not try fallback protocols.",
    )
    ap.add_argument(
        "--allow-multi-scheme",
        action="store_true",
        help="Keep testing after the first working protocol for the same endpoint.",
    )
    ap.add_argument(
        "--max-per-source",
        type=int,
        default=5000,
        help="Maximum proxies parsed from each source before testing.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Global maximum number of unique endpoints to test. 0 means no limit.",
    )
    ap.add_argument(
        "--source",
        action="append",
        default=[],
        help="Enable only selected built-in source names. Repeat to add more.",
    )
    ap.add_argument(
        "--list-sources",
        action="store_true",
        help="Print built-in source names and exit.",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="Print more progress information.",
    )
    return ap


def print_sources() -> None:
    for source in BUILTIN_SOURCES:
        hint = source.scheme_hint or "mixed"
        print(f"{source.name:<20} hint={hint:<7} urls={len(source.urls)}")


def validate_protocol_list(value: str) -> Tuple[str, ...]:
    protocols = tuple(normalize_scheme(part) or "" for part in value.split(",") if part.strip())
    protocols = tuple(part for part in protocols if part)
    if not protocols:
        fail("--protocols is empty.")
    invalid = [part for part in protocols if part not in PROTOCOLS]
    if invalid:
        fail(f"invalid protocols: {', '.join(invalid)}")
    return protocols


def print_summary(summary: Dict[str, object]) -> None:
    working_by_protocol = summary["working_by_protocol"]
    print(
        "Fetched and tested proxies from the current machine/network.",
        file=sys.stderr,
    )
    print(
        f"Tested candidates: {summary['tested_candidates']} | Working candidates: {summary['working_candidates']}",
        file=sys.stderr,
    )
    print(
        "Working by protocol: "
        f"http={working_by_protocol['http']} "
        f"socks4={working_by_protocol['socks4']} "
        f"socks5={working_by_protocol['socks5']}",
        file=sys.stderr,
    )
    print(json.dumps(summary["outputs"], indent=2), file=sys.stderr)


def main() -> int:
    args = parser().parse_args()

    if args.list_sources:
        print_sources()
        return 0

    workers = max(1, int(args.workers))
    retries = max(1, int(args.retries))
    max_per_source = max(0, int(args.max_per_source))
    global_limit = max(0, int(args.limit))
    protocols = validate_protocol_list(args.protocols)
    require_socks_if_needed(protocols)

    sources = selected_sources(args.source or None)
    probe_urls = tuple(args.probe_url) if args.probe_url else DEFAULT_PROBE_URLS
    target_urls = tuple(args.target_url) if args.target_url else DEFAULT_TARGET_URLS

    baseline_ip = None
    if args.require_ip_change:
        baseline_ip = detect_public_ip(args.connect_timeout, args.read_timeout)
        if baseline_ip is None:
            fail("failed to detect the direct public IP, cannot enforce --require-ip-change.", exit_code=1)

    settings = Settings(
        workers=workers,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        retries=retries,
        protocols=protocols,
        verify_protocol=bool(args.verify_protocol),
        allow_multi_scheme=bool(args.allow_multi_scheme),
        probe_urls=probe_urls,
        target_urls=target_urls,
        target_mode=args.target_mode,
        skip_target_check=bool(args.skip_target_check),
        require_ip_change=bool(args.require_ip_change),
        baseline_ip=baseline_ip,
    )

    started_at = time.time()
    candidates, source_stats = fetch_candidates(
        sources=sources,
        connect_timeout=settings.connect_timeout,
        read_timeout=settings.read_timeout,
        retries=settings.retries,
        max_per_source=max_per_source,
        global_limit=global_limit,
        verbose=args.verbose,
    )

    if not candidates:
        fail("no proxy candidates were fetched from the selected sources.", exit_code=1)

    if args.verbose:
        print(f"Unique endpoints queued for testing: {len(candidates)}", file=sys.stderr)

    results: List[CandidateResult] = []
    tested = 0
    working = 0
    max_pending = max(8, settings.workers * 4)

    with cf.ThreadPoolExecutor(max_workers=settings.workers) as executor:
        for item in iter_completed(executor, candidates, settings, max_pending=max_pending):
            tested += 1
            if item.results:
                results.append(item)
                working += 1
            if tested % 100 == 0 or tested == len(candidates):
                print(
                    f"Tested {tested}/{len(candidates)} candidates | working={working}",
                    file=sys.stderr,
                )

    summary = write_reports(
        output_dir=args.output_dir,
        source_stats=source_stats,
        candidates=candidates,
        results=results,
        settings=settings,
        started_at=started_at,
    )
    print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
