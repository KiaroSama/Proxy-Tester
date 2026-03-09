#!/usr/bin/env python3
"""
Fetch public proxies from multiple GitHub sources, test them on the current
machine/network, and write working proxies to a single text file immediately.

Highlights:
- asks how many working proxies you need (default: 50)
- checks/install runtime dependencies only when missing
- uses high async concurrency for faster testing
- saves each working proxy as soon as it is found
- stops exactly at the requested number of saved proxies
- prints colorized progress in the terminal
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote, urlsplit


USER_AGENT = "proxy-tester/5.0"
DEFAULT_NEED = 50
DEFAULT_WORKERS = 1000
DEFAULT_TIMEOUT = 3.0
DEFAULT_SOURCE_TIMEOUT = 20.0
DEFAULT_SOURCE_WORKERS = 24
DEFAULT_PER_SOURCE_LIMIT = 0
DEFAULT_TEST_URL = "https://ec.europa.eu/taxation_customs/vies/"
DEFAULT_IP_URL = "https://api.ipify.org?format=json"
TOKEN_SPLIT_RE = re.compile(r"[\s,;]+")
IPV4_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$"
)


@dataclass(frozen=True)
class SourceSpec:
    name: str
    urls: Tuple[str, ...]
    scheme_hint: Optional[str] = None
    max_items: int = 0


@dataclass(frozen=True)
class ProxyCandidate:
    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def key(self) -> Tuple[str, str, int, Optional[str], Optional[str]]:
        return (self.scheme, self.host, self.port, self.username, self.password)

    @property
    def proxy_url(self) -> str:
        auth = ""
        if self.username is not None:
            auth = quote(self.username, safe="")
            if self.password is not None:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        return f"{self.scheme}://{auth}{format_host(self.host)}:{self.port}"


@dataclass
class SourceResult:
    source: SourceSpec
    count: int
    error: Optional[str] = None


class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


USE_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def paint(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"{code}{text}{Ansi.RESET}"


SOURCES: Tuple[SourceSpec, ...] = (
    SourceSpec(
        name="proxifly_http",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="proxifly_https",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="proxifly_all",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
        ),
        scheme_hint=None,
        max_items=9000,
    ),
    SourceSpec(
        name="proxifly_socks4",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="proxifly_socks5",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="monosans_http",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="monosans_socks4",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="monosans_socks5",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="roosterkid_http",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="roosterkid_socks4",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="roosterkid_socks5",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="iplocate_all",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt",
        ),
        scheme_hint=None,
        max_items=9000,
    ),
    SourceSpec(
        name="iplocate_http",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="iplocate_https",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="iplocate_socks4",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="iplocate_socks5",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="speedx_http",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="speedx_socks4",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="speedx_socks5",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="zaeem_http",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="zaeem_socks4",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="zaeem_socks5",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="vakhov_http",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/http.txt",
            "https://vakhov.github.io/fresh-proxy-list/https.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="vakhov_socks4",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="vakhov_socks5",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="fyvri_http",
        urls=(
            "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/main/https.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="fyvri_socks4",
        urls=(
            "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/main/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="fyvri_socks5",
        urls=(
            "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/main/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="dpangestuw_http",
        urls=(
            "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="dpangestuw_socks4",
        urls=(
            "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="dpangestuw_socks5",
        urls=(
            "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="dpangestuw_all",
        urls=(
            "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/allive.txt",
        ),
        scheme_hint=None,
        max_items=9000,
    ),
    SourceSpec(
        name="joy_http",
        urls=(
            "https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/types/http/proxies.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="joy_socks4",
        urls=(
            "https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/types/socks4/proxies.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="joy_socks5",
        urls=(
            "https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/types/socks5/proxies.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="joy_all",
        urls=(
            "https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/proxies.txt",
        ),
        scheme_hint=None,
        max_items=9000,
    ),
    SourceSpec(
        name="kangproxy_raw",
        urls=(
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
        ),
        scheme_hint=None,
        max_items=7000,
    ),
    SourceSpec(
        name="kangproxy_http",
        urls=(
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
        ),
        scheme_hint="http",
        max_items=6000,
    ),
    SourceSpec(
        name="kangproxy_https",
        urls=(
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="kangproxy_socks4",
        urls=(
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="kangproxy_socks5",
        urls=(
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="kangproxy_all",
        urls=(
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/Proxies.txt",
        ),
        scheme_hint=None,
        max_items=9000,
    ),
    SourceSpec(
        name="gfp_http",
        urls=(
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt",
        ),
        scheme_hint="http",
        max_items=8000,
    ),
    SourceSpec(
        name="gfp_socks4",
        urls=(
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=8000,
    ),
    SourceSpec(
        name="gfp_socks5",
        urls=(
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=8000,
    ),
    SourceSpec(
        name="clarketm_http",
        urls=(
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        ),
        scheme_hint="http",
        max_items=4000,
    ),
    SourceSpec(
        name="aliilapro_http",
        urls=(
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="aliilapro_socks4",
        urls=(
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="aliilapro_socks5",
        urls=(
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="themiralay_http",
        urls=(
            "https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt",
        ),
        scheme_hint="http",
        max_items=1000,
    ),
    SourceSpec(
        name="firmfox_http",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/http.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="firmfox_https",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/https.txt",
        ),
        scheme_hint="http",
        max_items=5000,
    ),
    SourceSpec(
        name="firmfox_socks4",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
        max_items=5000,
    ),
    SourceSpec(
        name="firmfox_socks5",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/socks5.txt",
        ),
        scheme_hint="socks5",
        max_items=5000,
    ),
    SourceSpec(
        name="mishakorzik_http",
        urls=(
            "https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/proxy.txt",
            "https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/packages/Proxy.txt",
        ),
        scheme_hint="http",
        max_items=4000,
    ),
    SourceSpec(
        name="loneking_all",
        urls=(
            "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/all.txt",
        ),
        scheme_hint=None,
        max_items=9000,
    ),
)


def _python_version_ok() -> bool:
    return sys.version_info >= (3, 8)


def _try_install(package: str) -> bool:
    commands = (
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--quiet",
            package,
        ],
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--quiet",
            "--user",
            package,
        ],
    )
    for command in commands:
        try:
            subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            continue
    return False


def _import_or_install(import_name: str, package_name: Optional[str] = None):
    try:
        return importlib.import_module(import_name)
    except Exception:
        package = package_name or import_name
        print(f"Installing missing dependency: {package}", file=sys.stderr)
        if not _try_install(package):
            raise RuntimeError(f"Missing dependency '{package}' and auto-install failed.")
        return importlib.import_module(import_name)


def ensure_runtime_deps():
    aiohttp = _import_or_install("aiohttp")
    aiohttp_socks = _import_or_install("aiohttp_socks", "aiohttp-socks")
    return aiohttp, aiohttp_socks


def maybe_raise_nofile_limit(expected_connections: int) -> None:
    try:
        import resource
    except Exception:
        return

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard == resource.RLIM_INFINITY:
            target = max(soft, min(65535, expected_connections * 4 + 2048))
        else:
            target = min(hard, max(soft, expected_connections * 4 + 2048))
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        return


def normalize_scheme(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower()
    if value == "https":
        return "http"
    if value in {"http", "socks4", "socks5"}:
        return value
    return None


def format_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def normalize_host(host: str) -> Optional[str]:
    host = host.strip().strip("[]").lower()
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
    return token.rstrip(".:")


def parse_host_port(raw: str) -> Optional[Tuple[str, int, Optional[str], Optional[str]]]:
    token = strip_token(raw)
    if not token or token.startswith("#"):
        return None

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
        if not normalized_host:
            return None
        return normalized_host, port, split.username, split.password

    username: Optional[str] = None
    password: Optional[str] = None
    host_port = token

    if "@" in token:
        auth, _, host_port = token.rpartition("@")
        if ":" in auth:
            username, password = auth.split(":", 1)
        else:
            username, password = auth, None

    if host_port.startswith("[") and "]:" in host_port:
        close = host_port.find("]")
        host = host_port[1:close]
        port_text = host_port[close + 2 :]
    else:
        if ":" not in host_port:
            return None
        host, port_text = host_port.rsplit(":", 1)

    normalized_host = normalize_host(host)
    port = valid_port(port_text)
    if not normalized_host or port is None:
        return None

    return normalized_host, port, username, password


def parse_proxy_token(token: str, default_scheme: Optional[str]) -> Optional[ProxyCandidate]:
    token = strip_token(token)
    if not token or token.startswith("#"):
        return None

    scheme = default_scheme
    if "://" in token:
        scheme = normalize_scheme(urlsplit(token).scheme)
    if not scheme:
        return None

    parsed = parse_host_port(token)
    if not parsed:
        return None
    host, port, username, password = parsed
    return ProxyCandidate(
        scheme=scheme,
        host=host,
        port=port,
        username=username,
        password=password,
    )


def extract_ip(text: str) -> Optional[str]:
    try:
        data = json.loads(text)
        for key in ("ip", "origin"):
            value = data.get(key)
            if isinstance(value, str):
                for part in [x.strip() for x in value.split(",") if x.strip()]:
                    if IPV4_EXTRACT_RE.fullmatch(part):
                        return part
    except Exception:
        pass

    match = IPV4_EXTRACT_RE.search(text)
    return match.group(0) if match else None


async def read_text_tokens(response, source: SourceSpec, per_source_limit: int) -> List[ProxyCandidate]:
    limit = source.max_items or per_source_limit
    if source.max_items and per_source_limit > 0:
        limit = min(source.max_items, per_source_limit)
    elif per_source_limit > 0:
        limit = per_source_limit
    if limit <= 0:
        limit = 1_000_000

    found: List[ProxyCandidate] = []
    seen = set()
    buffer = ""

    async for chunk in response.content.iter_chunked(65536):
        buffer += chunk.decode("utf-8", errors="ignore")
        parts = TOKEN_SPLIT_RE.split(buffer)
        buffer = parts.pop() if parts else ""
        for token in parts:
            candidate = parse_proxy_token(token, source.scheme_hint)
            if candidate is None:
                continue
            if candidate.key in seen:
                continue
            seen.add(candidate.key)
            found.append(candidate)
            if len(found) >= limit:
                return found

    if buffer:
        candidate = parse_proxy_token(buffer, source.scheme_hint)
        if candidate is not None and candidate.key not in seen:
            found.append(candidate)

    return found[:limit]


async def fetch_one_source(session, source: SourceSpec, per_source_limit: int) -> Tuple[SourceResult, List[ProxyCandidate]]:
    last_error: Optional[str] = None
    for url in source.urls:
        try:
            async with session.get(url, allow_redirects=True) as response:
                if response.status >= 400:
                    last_error = f"HTTP {response.status}"
                    continue
                items = await read_text_tokens(response, source, per_source_limit)
                return SourceResult(source=source, count=len(items), error=None), items
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_error = str(exc)
    return SourceResult(source=source, count=0, error=last_error or "download failed"), []


async def fetch_all_sources(args) -> Tuple[List[ProxyCandidate], List[SourceResult]]:
    aiohttp, _ = ensure_runtime_deps()
    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=max(5.0, args.source_timeout))
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, enable_cleanup_closed=True)
    semaphore = asyncio.Semaphore(max(1, args.source_workers))

    async def bounded_fetch(session, source: SourceSpec):
        async with semaphore:
            return await fetch_one_source(session, source, args.per_source_limit)

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=headers,
        trust_env=False,
    ) as session:
        tasks = [asyncio.create_task(bounded_fetch(session, source)) for source in SOURCES]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

    ordered_lists: List[List[ProxyCandidate]] = []
    results: List[SourceResult] = []
    for source, item in zip(SOURCES, gathered):
        if isinstance(item, Exception):
            results.append(SourceResult(source=source, count=0, error=str(item)))
            ordered_lists.append([])
            continue
        result, candidates = item
        results.append(result)
        ordered_lists.append(candidates)

    merged: Dict[Tuple[str, str, int, Optional[str], Optional[str]], ProxyCandidate] = {}
    for candidates in ordered_lists:
        for candidate in candidates:
            merged.setdefault(candidate.key, candidate)

    return list(merged.values()), results


class ResultWriter:
    def __init__(self, path: str):
        self.path = path
        self.handle = None

    def __enter__(self):
        output_path = Path(self.path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("", encoding="utf-8")
        self.handle = output_path.open("a", encoding="utf-8", buffering=1, newline="\n")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handle is not None:
            self.handle.close()

    def write_line(self, line: str) -> None:
        if self.handle is None:
            raise RuntimeError("Writer is not open.")
        self.handle.write(line + "\n")
        self.handle.flush()
        try:
            os.fsync(self.handle.fileno())
        except Exception:
            pass


class SharedState:
    def __init__(self, need: int):
        self.need = need
        self.tested = 0
        self.found = 0
        self.next_index = 0
        self.seen_working = set()
        self.stop_event = asyncio.Event()
        self.index_lock = asyncio.Lock()
        self.result_lock = asyncio.Lock()
        self.started_at = time.time()


async def read_small_text(response, limit: int = 2048) -> str:
    data = await response.content.read(limit)
    return data.decode("utf-8", errors="ignore")


async def fetch_direct_ip(http_session, ip_url: str) -> Optional[str]:
    try:
        async with http_session.get(ip_url, allow_redirects=True) as response:
            if response.status >= 400:
                return None
            return extract_ip(await read_small_text(response, limit=4096))
    except Exception:
        return None


async def request_via_proxy(http_session, ProxyConnector, aiohttp, candidate: ProxyCandidate, url: str, timeout_s: float) -> Tuple[bool, Optional[str]]:
    if candidate.scheme == "http":
        try:
            async with http_session.get(url, proxy=candidate.proxy_url, allow_redirects=True) as response:
                if response.status >= 400:
                    return False, None
                return True, await read_small_text(response, limit=4096)
        except Exception:
            return False, None

    try:
        connector = ProxyConnector.from_url(candidate.proxy_url)
        client_timeout = aiohttp.ClientTimeout(total=max(0.5, timeout_s))
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=client_timeout,
            headers={"User-Agent": USER_AGENT},
            trust_env=False,
        ) as session:
            async with session.get(url, allow_redirects=True) as response:
                if response.status >= 400:
                    return False, None
                return True, await read_small_text(response, limit=4096)
    except Exception:
        return False, None


async def test_candidate(http_session, ProxyConnector, aiohttp, candidate: ProxyCandidate, args, baseline_ip: Optional[str]) -> bool:
    ok, _ = await request_via_proxy(http_session, ProxyConnector, aiohttp, candidate, args.test_url, args.timeout)
    if not ok:
        return False

    if args.require_different_ip:
        if not baseline_ip:
            return False
        ok, text = await request_via_proxy(http_session, ProxyConnector, aiohttp, candidate, args.ip_url, args.timeout)
        if not ok or not text:
            return False
        observed_ip = extract_ip(text)
        if not observed_ip or observed_ip == baseline_ip:
            return False

    return True


def status_line(tested: int, total: int, found: int, need: int, workers: int) -> str:
    tested_text = paint(f"Tested {tested}/{total}", Ansi.CYAN)
    working_text = paint(f"working={found}", Ansi.GREEN if found > 0 else Ansi.DIM)
    need_text = paint(f"need={need}", Ansi.YELLOW)
    workers_text = paint(f"concurrency={workers}", Ansi.MAGENTA)
    return f"{tested_text} | {working_text} | {need_text} | {workers_text}"


async def progress_loop(state: SharedState, total: int, workers: int) -> None:
    while not state.stop_event.is_set():
        async with state.result_lock:
            line = status_line(state.tested, total, state.found, state.need, workers)
        print("\r" + line + " " * 10, end="", file=sys.stderr, flush=True)
        await asyncio.sleep(0.35)

    async with state.result_lock:
        line = status_line(state.tested, total, state.found, state.need, workers)
    print("\r" + line + " " * 10, file=sys.stderr, flush=True)


async def worker_loop(
    state: SharedState,
    candidates: Sequence[ProxyCandidate],
    http_session,
    ProxyConnector,
    aiohttp,
    args,
    baseline_ip: Optional[str],
    writer: ResultWriter,
) -> None:
    while not state.stop_event.is_set():
        async with state.index_lock:
            if state.stop_event.is_set() or state.next_index >= len(candidates):
                return
            index = state.next_index
            state.next_index += 1

        candidate = candidates[index]
        ok = await test_candidate(http_session, ProxyConnector, aiohttp, candidate, args, baseline_ip)

        async with state.result_lock:
            state.tested += 1
            if not ok:
                continue
            proxy_url = candidate.proxy_url
            if proxy_url in state.seen_working:
                continue
            if state.found >= state.need:
                state.stop_event.set()
                return
            state.seen_working.add(proxy_url)
            state.found += 1
            writer.write_line(proxy_url)
            if state.found >= state.need:
                state.stop_event.set()
                return


async def run_checks(candidates: Sequence[ProxyCandidate], args) -> Tuple[int, int, float, Optional[str]]:
    aiohttp, aiohttp_socks = ensure_runtime_deps()
    ProxyConnector = aiohttp_socks.ProxyConnector

    maybe_raise_nofile_limit(args.workers)

    timeout = aiohttp.ClientTimeout(total=max(0.5, args.timeout))
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, enable_cleanup_closed=True)
    headers = {"User-Agent": USER_AGENT}
    state = SharedState(need=args.need)

    with ResultWriter(args.output) as writer:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            trust_env=False,
        ) as http_session:
            baseline_ip = None
            if args.require_different_ip:
                baseline_ip = await fetch_direct_ip(http_session, args.ip_url)
                if not baseline_ip:
                    print(
                        paint(
                            "Warning: could not detect baseline IP, strict IP-change mode was disabled.",
                            Ansi.YELLOW,
                        ),
                        file=sys.stderr,
                    )
                    args.require_different_ip = False

            progress_task = asyncio.create_task(progress_loop(state, len(candidates), args.workers))
            workers = [
                asyncio.create_task(
                    worker_loop(state, candidates, http_session, ProxyConnector, aiohttp, args, baseline_ip, writer)
                )
                for _ in range(max(1, args.workers))
            ]
            stop_waiter = asyncio.create_task(state.stop_event.wait())
            gather_future = asyncio.gather(*workers, return_exceptions=True)

            try:
                done, _ = await asyncio.wait(
                    {gather_future, stop_waiter},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if stop_waiter in done and not gather_future.done():
                    for task in workers:
                        task.cancel()
                    await asyncio.gather(*workers, return_exceptions=True)
                else:
                    state.stop_event.set()
            finally:
                state.stop_event.set()
                if not stop_waiter.done():
                    stop_waiter.cancel()
                    await asyncio.gather(stop_waiter, return_exceptions=True)
                await asyncio.gather(progress_task, return_exceptions=True)

    elapsed = time.time() - state.started_at
    return state.tested, state.found, elapsed, baseline_ip


def prompt_for_need(default_need: int = DEFAULT_NEED) -> int:
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


def auto_per_source_limit(need: int) -> int:
    return min(12000, max(3000, need * 120))


def print_source_summary(results: Iterable[SourceResult], total_unique: int) -> None:
    ok_count = sum(1 for item in results if not item.error)
    source_total = sum(1 for _ in results)
    print(
        f"{paint('Fetched sources', Ansi.BLUE)}: {ok_count}/{source_total} | "
        f"{paint('unique candidates', Ansi.CYAN)}: {total_unique:,}",
        file=sys.stderr,
    )


def list_sources() -> None:
    for item in SOURCES:
        hint = item.scheme_hint or "mixed"
        print(f"{item.name}\t{hint}\t{item.urls[0]}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Fetch public proxies from many GitHub sources and save working ones to one file."
    )
    ap.add_argument("--need", type=int, default=0, help="How many working proxies to save.")
    ap.add_argument(
        "-o",
        "--output",
        default="working_proxies.txt",
        help="Single output file for working proxies.",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent proxy checks (default: {DEFAULT_WORKERS}).",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    ap.add_argument(
        "--test-url",
        default=DEFAULT_TEST_URL,
        help="URL used to verify proxy reachability.",
    )
    ap.add_argument(
        "--ip-url",
        default=DEFAULT_IP_URL,
        help="URL used to detect public IP in strict mode.",
    )
    ap.add_argument(
        "--require-different-ip",
        action="store_true",
        help="Only keep proxies that change the observed public IP.",
    )
    ap.add_argument(
        "--source-timeout",
        type=float,
        default=DEFAULT_SOURCE_TIMEOUT,
        help=f"Timeout for source downloads (default: {DEFAULT_SOURCE_TIMEOUT}).",
    )
    ap.add_argument(
        "--source-workers",
        type=int,
        default=DEFAULT_SOURCE_WORKERS,
        help=f"Concurrent source downloads (default: {DEFAULT_SOURCE_WORKERS}).",
    )
    ap.add_argument(
        "--per-source-limit",
        type=int,
        default=DEFAULT_PER_SOURCE_LIMIT,
        help="Max parsed proxies per source. 0 = automatic.",
    )
    ap.add_argument(
        "--list-sources",
        action="store_true",
        help="Print built-in sources and exit.",
    )
    return ap


async def async_main(args) -> int:
    candidates, source_results = await fetch_all_sources(args)
    if not candidates:
        print(paint("ERROR: no candidates fetched from any source.", Ansi.RED), file=sys.stderr)
        return 1

    print_source_summary(source_results, len(candidates))

    tested, found, elapsed, baseline_ip = await run_checks(candidates, args)
    abs_out = os.path.abspath(args.output)

    print(
        f"Saved {paint(str(found), Ansi.GREEN)} working proxies to: {abs_out}",
        file=sys.stderr,
    )
    print(
        f"tested={tested:,} | workers={args.workers} | timeout={args.timeout}s | elapsed={elapsed:.2f}s",
        file=sys.stderr,
    )
    if baseline_ip:
        print(f"baseline_ip={baseline_ip}", file=sys.stderr)
    return 0


def main() -> int:
    if not _python_version_ok():
        print("ERROR: Please run with Python 3.8+.", file=sys.stderr)
        return 2

    parser = build_parser()
    args = parser.parse_args()

    if args.list_sources:
        list_sources()
        return 0

    if args.need <= 0:
        args.need = prompt_for_need(DEFAULT_NEED)

    args.workers = max(1, int(args.workers))
    args.timeout = max(0.5, float(args.timeout))
    args.source_workers = max(1, int(args.source_workers))
    args.per_source_limit = int(args.per_source_limit)
    if args.per_source_limit <= 0:
        args.per_source_limit = auto_per_source_limit(args.need)

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted. Saved results remain in the output file.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
