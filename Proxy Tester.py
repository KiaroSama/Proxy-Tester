#!/usr/bin/env python3
"""
Fetch public proxies from multiple public sources, test them on the current
machine/network, detect the working protocol, and save working results into one
output file.

This version:
- asks how many working proxies you need
- auto-installs missing dependencies only when required
- uses aggressive concurrency
- stops early after enough working proxies are found
- writes a single mixed output file
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import importlib
import importlib.util
import ipaddress
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, NoReturn, Optional, Sequence, Set, Tuple
from urllib.parse import quote, urlsplit


requests = None
HAS_PYSOCKS = False
USER_AGENT = "proxy-tester/3.0"
PROTOCOLS: Tuple[str, ...] = ("http", "socks4", "socks5")
DEFAULT_NEED = 50
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
_thread_local = threading.local()
_session_pool_size = 128


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
        return f"{scheme}://{auth}{format_host(self.host)}:{self.port}"


@dataclass
class SchemeResult:
    scheme: str
    latency_ms: float
    exit_ip: Optional[str]
    ip_changed: Optional[bool]


@dataclass
class CandidateResult:
    candidate: ProxyCandidate
    results: List[SchemeResult]


@dataclass
class WorkingProxy:
    proxy_url: str
    scheme: str
    latency_ms: float
    endpoint: str
    exit_ip: Optional[str]
    source_count: int


@dataclass
class Settings:
    need_count: int
    workers: int
    max_pending: int
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


def fail(message: str, exit_code: int = 2) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def install_packages(packages: Sequence[str]) -> bool:
    unique = [item for item in dict.fromkeys(packages) if item]
    if not unique:
        return True

    commands = (
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *unique],
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--user", *unique],
    )
    for command in commands:
        try:
            subprocess.check_call(command)
            return True
        except Exception:
            continue
    return False


def ensure_requests() -> None:
    global requests
    if requests is not None:
        return
    if not module_available("requests"):
        print("Installing missing dependency: requests", file=sys.stderr)
        if not install_packages(("requests",)):
            fail("failed to install requests automatically.", exit_code=1)
        importlib.invalidate_caches()
    try:
        import requests as imported_requests  # type: ignore
    except Exception as exc:
        fail(f"failed to import requests: {exc}", exit_code=1)
    requests = imported_requests


HAS_PYSOCKS = module_available("socks")


def ensure_socks_if_needed(protocols: Sequence[str]) -> None:
    global HAS_PYSOCKS
    if not any(proto.startswith("socks") for proto in protocols):
        return
    if HAS_PYSOCKS:
        return
    print("Installing missing dependency: PySocks", file=sys.stderr)
    if not install_packages(("PySocks",)):
        fail('failed to install PySocks automatically. Try: pip install "requests[socks]"', exit_code=1)
    importlib.invalidate_caches()
    HAS_PYSOCKS = module_available("socks")
    if not HAS_PYSOCKS:
        fail('PySocks is still unavailable. Try: pip install "requests[socks]"', exit_code=1)


def normalize_scheme(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower()
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
    token = token.strip('"\'`<>(){}')
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
        normalized = normalize_host(host)
        if normalized is None:
            return None
        return normalized, port, split.username, split.password

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
    normalized = normalize_host(host)
    if normalized is None:
        return None
    return normalized, port, username, password


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


def configure_session_pool(workers: int) -> None:
    global _session_pool_size
    _session_pool_size = max(64, min(2048, workers * 4))


def build_session():
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=_session_pool_size,
        pool_maxsize=_session_pool_size,
        max_retries=0,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def direct_session():
    return build_session()


def worker_session():
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = build_session()
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
                    time.sleep(min(0.25 * (2 ** attempt), 1.5))
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


def fetch_one_source(
    source: SourceSpec,
    connect_timeout: float,
    read_timeout: float,
    retries: int,
    max_per_source: int,
) -> Tuple[str, List[ProxyCandidate], Dict[str, object]]:
    stat: Dict[str, object] = {
        "hint": source.scheme_hint,
        "urls": list(source.urls),
        "downloaded": False,
        "parsed": 0,
        "unique_added": 0,
        "error": None,
    }
    try:
        text = download_text(
            source.urls,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=retries,
        )
        parsed = parse_proxy_text(text, fallback_scheme=source.scheme_hint, max_items=max_per_source)
        stat["downloaded"] = True
        stat["parsed"] = len(parsed)
        return source.name, parsed, stat
    except BaseException as exc:
        stat["error"] = str(exc)
        return source.name, [], stat


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

    fetch_workers = max(4, min(24, len(sources)))
    with cf.ThreadPoolExecutor(max_workers=fetch_workers) as executor:
        futures = {
            executor.submit(
                fetch_one_source,
                source,
                connect_timeout,
                read_timeout,
                retries,
                max_per_source,
            ): source
            for source in sources
        }
        for future in cf.as_completed(futures):
            source = futures[future]
            name, parsed, stat = future.result()
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
                existing.sources.add(name)
                existing.hints.update(candidate.hints)
            stat["unique_added"] = added
            stats[name] = stat
            if verbose:
                if stat["error"]:
                    print(f"Failed {source.name}: {stat['error']}", file=sys.stderr)
                else:
                    print(
                        f"Fetched {source.name}: parsed={stat['parsed']} unique_added={stat['unique_added']}",
                        file=sys.stderr,
                    )

    candidates = list(merged.values())
    candidates.sort(
        key=lambda item: (
            -len(item.sources),
            -len(item.hints),
            item.port,
            item.host,
        )
    )
    if global_limit > 0:
        candidates = candidates[:global_limit]
    return candidates, stats


def proxy_mapping(scheme: str, candidate: ProxyCandidate) -> Dict[str, str]:
    if scheme == "socks5":
        proxy_url = candidate.proxy_url("socks5h")
    elif scheme == "socks4":
        proxy_url = candidate.proxy_url("socks4a")
    else:
        proxy_url = candidate.proxy_url("http")
    return {"http": proxy_url, "https": proxy_url}


def read_small_text(response, limit: int = 4096) -> str:
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
    session,
    candidate: ProxyCandidate,
    scheme: str,
    url: str,
    timeout: Tuple[float, float],
    need_ip: bool,
) -> Tuple[bool, Optional[float], Optional[str]]:
    started = time.perf_counter()
    response = None
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
        hinted = [scheme for scheme in settings.protocols if scheme in candidate.hints]
        return hinted or list(settings.protocols)
    hinted = [scheme for scheme in settings.protocols if scheme in candidate.hints]
    remaining = [scheme for scheme in settings.protocols if scheme not in candidate.hints]
    return hinted + remaining


def probe_scheme(session, candidate: ProxyCandidate, scheme: str, settings: Settings, stop_event: threading.Event) -> Optional[Tuple[float, Optional[str]]]:
    for url in settings.probe_urls:
        if stop_event.is_set():
            return None
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


def target_check(session, candidate: ProxyCandidate, scheme: str, settings: Settings, stop_event: threading.Event) -> bool:
    if settings.skip_target_check or not settings.target_urls:
        return True

    matched = 0
    for url in settings.target_urls:
        if stop_event.is_set():
            return False
        ok, _, _ = request_via_proxy(
            session=session,
            candidate=candidate,
            scheme=scheme,
            url=url,
            timeout=settings.request_timeout,
            need_ip=False,
        )
        if ok:
            matched += 1
            if settings.target_mode == "any":
                return True
        elif settings.target_mode == "all":
            return False

    if settings.target_mode == "all":
        return matched == len(settings.target_urls)
    return matched > 0


def test_candidate(candidate: ProxyCandidate, settings: Settings, stop_event: threading.Event) -> CandidateResult:
    if stop_event.is_set():
        return CandidateResult(candidate=candidate, results=[])

    session = worker_session()
    results: List[SchemeResult] = []

    for scheme in protocol_order(candidate, settings):
        if stop_event.is_set():
            break
        if scheme != "http" and not HAS_PYSOCKS:
            continue

        probe = probe_scheme(session=session, candidate=candidate, scheme=scheme, settings=settings, stop_event=stop_event)
        if probe is None:
            continue
        latency_ms, exit_ip = probe

        ip_changed: Optional[bool] = None
        if settings.baseline_ip and exit_ip:
            ip_changed = exit_ip != settings.baseline_ip
            if settings.require_ip_change and not ip_changed:
                continue

        if not target_check(
            session=session,
            candidate=candidate,
            scheme=scheme,
            settings=settings,
            stop_event=stop_event,
        ):
            continue

        results.append(
            SchemeResult(
                scheme=scheme,
                latency_ms=latency_ms,
                exit_ip=exit_ip,
                ip_changed=ip_changed,
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
    stop_event: threading.Event,
) -> Iterator[CandidateResult]:
    pending: Dict[cf.Future[CandidateResult], ProxyCandidate] = {}
    iterator = iter(candidates)

    while True:
        while not stop_event.is_set() and len(pending) < settings.max_pending:
            try:
                candidate = next(iterator)
            except StopIteration:
                break
            future = executor.submit(test_candidate, candidate, settings, stop_event)
            pending[future] = candidate

        if stop_event.is_set():
            for future in list(pending):
                if future.cancel():
                    pending.pop(future, None)

        if not pending:
            break

        done, _ = cf.wait(pending.keys(), return_when=cf.FIRST_COMPLETED)
        for future in done:
            candidate = pending.pop(future, None)
            if future.cancelled():
                continue
            try:
                yield future.result()
            except Exception:
                if candidate is not None:
                    yield CandidateResult(candidate=candidate, results=[])


def write_output(path: str, items: Iterable[WorkingProxy]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for item in items:
            handle.write(item.proxy_url + "\n")


def prompt_need_count(default_need: int = DEFAULT_NEED) -> int:
    if not sys.stdin or not sys.stdin.isatty():
        return default_need

    while True:
        try:
            raw = input(f"How many working proxies do you need? [{default_need}]: ").strip()
            if not raw:
                return default_need
            value = int(raw)
            if value < 1:
                print("Please enter a number >= 1.")
                continue
            return value
        except KeyboardInterrupt:
            print("\nCancelled by user.", file=sys.stderr)
            raise
        except Exception:
            print("Please enter a valid integer.")


def default_workers(need_count: int) -> int:
    cpu = os.cpu_count() or 4
    aggressive = max(cpu * 48, need_count * 5)
    return max(128, min(512, aggressive))


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Fetch and validate public proxies on the machine where this script runs."
    )
    ap.add_argument("-o", "--output", default="working_proxies.txt", help="Single output file.")
    ap.add_argument(
        "--need",
        type=int,
        default=0,
        help=f"How many working proxies to save. 0 means prompt or default {DEFAULT_NEED}.",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Concurrent tests. 0 uses an aggressive automatic value.",
    )
    ap.add_argument(
        "--connect-timeout",
        type=float,
        default=2.5,
        help="Connect timeout per request in seconds.",
    )
    ap.add_argument(
        "--read-timeout",
        type=float,
        default=3.5,
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
        help="Protocol probe URL. Repeat to add more.",
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
        help="Only validate the protocol and skip final target-site validation.",
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
        help="Try fallback protocols if the source hint is wrong.",
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
        help="Keep multiple working schemes for the same endpoint.",
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
    raw_parts = [part.strip() for part in value.split(",") if part.strip()]
    if not raw_parts:
        fail("--protocols is empty.")

    protocols: List[str] = []
    invalid: List[str] = []
    for part in raw_parts:
        normalized = normalize_scheme(part)
        if normalized is None:
            invalid.append(part)
            continue
        protocols.append(normalized)

    if invalid:
        fail(f"invalid protocols: {', '.join(invalid)}")
    return tuple(protocols)


def print_summary(
    output_path: str,
    wanted: int,
    saved: int,
    tested: int,
    total_candidates: int,
    workers: int,
    elapsed_seconds: float,
    baseline_ip: Optional[str],
) -> None:
    print(
        f"Saved {saved}/{wanted} working proxies to: {os.path.abspath(output_path)}",
        file=sys.stderr,
    )
    print(
        f"Tested candidates: {tested}/{total_candidates} | workers={workers} | elapsed={elapsed_seconds:.2f}s",
        file=sys.stderr,
    )
    if baseline_ip:
        print(f"Direct public IP: {baseline_ip}", file=sys.stderr)


def main() -> int:
    args = parser().parse_args()

    if args.list_sources:
        print_sources()
        return 0

    need_count = max(1, int(args.need)) if args.need and args.need > 0 else prompt_need_count(DEFAULT_NEED)
    protocols = validate_protocol_list(args.protocols)
    ensure_requests()
    ensure_socks_if_needed(protocols)

    workers = max(1, int(args.workers)) if args.workers and args.workers > 0 else default_workers(need_count)
    max_pending = max(workers + 64, workers * 2)
    retries = max(1, int(args.retries))
    max_per_source = max(0, int(args.max_per_source))
    global_limit = max(0, int(args.limit))

    configure_session_pool(workers)

    sources = selected_sources(args.source or None)
    probe_urls = tuple(args.probe_url) if args.probe_url else DEFAULT_PROBE_URLS
    target_urls = tuple(args.target_url) if args.target_url else DEFAULT_TARGET_URLS

    baseline_ip = None
    if args.require_ip_change:
        baseline_ip = detect_public_ip(args.connect_timeout, args.read_timeout)
        if baseline_ip is None:
            fail("failed to detect the direct public IP, cannot enforce --require-ip-change.", exit_code=1)

    settings = Settings(
        need_count=need_count,
        workers=workers,
        max_pending=max_pending,
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

    downloaded_sources = sum(1 for stat in source_stats.values() if stat.get("downloaded"))
    if args.verbose:
        print(
            f"Sources loaded: {downloaded_sources}/{len(source_stats)} | queued endpoints: {len(candidates)}",
            file=sys.stderr,
        )

    stop_event = threading.Event()
    working: List[WorkingProxy] = []
    seen_proxy_urls: Set[str] = set()
    tested = 0
    last_progress = 0.0

    with cf.ThreadPoolExecutor(max_workers=settings.workers) as executor:
        for item in iter_completed(executor, candidates, settings, stop_event):
            tested += 1
            for result in item.results:
                proxy_url = item.candidate.proxy_url(result.scheme)
                if proxy_url in seen_proxy_urls:
                    continue
                seen_proxy_urls.add(proxy_url)
                working.append(
                    WorkingProxy(
                        proxy_url=proxy_url,
                        scheme=result.scheme,
                        latency_ms=result.latency_ms,
                        endpoint=item.candidate.endpoint,
                        exit_ip=result.exit_ip,
                        source_count=len(item.candidate.sources),
                    )
                )

            if len(working) >= settings.need_count and not stop_event.is_set():
                stop_event.set()
                print(
                    f"Reached target: {len(working)} working proxies. Finishing queued tests...",
                    file=sys.stderr,
                )

            now = time.time()
            if tested == len(candidates) or (now - last_progress) >= 1.0:
                print(
                    f"Tested {tested}/{len(candidates)} | working={len(working)} | pending_limit={settings.max_pending}",
                    file=sys.stderr,
                )
                last_progress = now

    working.sort(key=lambda item: (item.latency_ms, -item.source_count, item.proxy_url))
    selected = working[: settings.need_count]
    write_output(args.output, selected)

    print_summary(
        output_path=args.output,
        wanted=settings.need_count,
        saved=len(selected),
        tested=tested,
        total_candidates=len(candidates),
        workers=settings.workers,
        elapsed_seconds=time.time() - started_at,
        baseline_ip=baseline_ip,
    )

    if len(selected) < settings.need_count:
        print(
            "Warning: fewer working proxies were found than requested. "
            "Try increasing --limit, lowering timeouts, or disabling strict filters.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
