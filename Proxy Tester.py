#!/usr/bin/env python3
"""
Fetch public proxies from curated public sources, test them on the current
machine/network, and write working proxies to a single text file immediately.

Highlights:
- asks how many working proxies you need (default: 50)
- installs runtime dependencies only when missing
- uses high async concurrency for faster testing
- pre-checks source health before full downloads
- saves each working proxy as soon as it is found
- stops exactly at the requested number of saved proxies
- runs repeat reachability checks for more reliable working proxies
- trims the slow tail of hanging candidates once the queue is empty
- prefers high-confidence, actively maintained proxy sources
- prints colorized progress in the terminal
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import importlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import time
from collections import defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote, urlsplit


# Basic runtime defaults.
USER_AGENT = "proxy-tester/6.0"
DEFAULT_NEED = 50
DEFAULT_TIMEOUT = 2.5
DEFAULT_SOURCE_TIMEOUT = 15.0
DEFAULT_SOURCE_HEALTH_TIMEOUT = 4.5
DEFAULT_SOURCE_HEALTH_BYTES = 16384
DEFAULT_SOURCE_WORKERS = 20
DEFAULT_PER_SOURCE_LIMIT = 0
DEFAULT_SOURCE_BATCH_SIZE = 10
DEFAULT_CANDIDATE_MULTIPLIER = 60
RECENT_RATE_WINDOW = 4.0
PROBE_DEADLINE_GRACE = 0.15
STRICT_IP_TIMEOUT_CAP = 1.5
DEFAULT_STABILITY_CHECKS = 1
DEFAULT_STABILITY_TIMEOUT_FACTOR = 0.8
DEFAULT_TAIL_DRAIN_TIMEOUT = 0.9
DEFAULT_TAIL_EMPTY_TIMEOUT = 0.0
WRITER_CLOSE_TIMEOUT = 0.25
DEFAULT_TEST_URLS: Tuple[str, ...] = (
    "http://www.gstatic.com/generate_204",
)
DEFAULT_IP_URL = "https://api.ipify.org?format=json"
SCHEME_ORDER: Tuple[str, ...] = ("http", "socks5", "socks4")
TOKEN_SPLIT_RE = re.compile(r"[\s,;]+")
IPV4_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$"
)


def default_worker_count() -> int:
    """Use aggressive concurrency for large public proxy batches."""
    return 3000


DEFAULT_WORKERS = default_worker_count()


@dataclass(frozen=True)
class SourceSpec:
    """Describe one proxy source and how much we trust or prefer it."""

    name: str
    urls: Tuple[str, ...]
    scheme_hint: str
    priority: int = 50
    max_items: int = 0
    min_items: int = 1


@dataclass(frozen=True)
class ProxyCandidate:
    """Represent one proxy candidate plus some lightweight source metadata."""

    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    source_name: str = ""
    source_priority: int = 100

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


@dataclass(frozen=True)
class ProbeTarget:
    """Store parsed URL parts once so workers do not re-parse for every proxy."""

    raw_url: str
    scheme: str
    host: str
    port: int
    path_qs: str
    expected_status: Optional[int] = None


@dataclass
class SourceResult:
    """Keep a short fetch summary for one source."""

    source: SourceSpec
    count: int
    url_used: Optional[str] = None
    error: Optional[str] = None


class Ansi:
    """Small ANSI color helper used only for terminal status output."""

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


# Keep the Windows event loop quieter for harmless reset noise.
def _connector_cleanup_closed_enabled() -> bool:
    return os.name != "nt"


# Ignore a well-known benign Windows transport reset warning.
def _is_benign_windows_proactor_reset(context: dict) -> bool:
    if os.name != "nt":
        return False
    exc = context.get("exception")
    if not isinstance(exc, ConnectionResetError):
        return False
    if getattr(exc, "winerror", None) != 10054:
        return False
    message = str(context.get("message") or "")
    handle = context.get("handle")
    handle_repr = repr(handle) if handle is not None else ""
    probe = f"{message} {handle_repr}"
    return "_ProactorBasePipeTransport._call_connection_lost" in probe


# Ignore noisy Windows overlapped-cancel warnings during aggressive cancellation.
def _is_benign_windows_overlapped_cancel(context: dict) -> bool:
    if os.name != "nt":
        return False
    message = str(context.get("message") or "")
    if "Cancelling an overlapped future failed" not in message:
        return False
    exc = context.get("exception")
    if not isinstance(exc, OSError):
        return False
    return getattr(exc, "winerror", None) in {6, 10038}


# Install the Windows-specific exception filter once per event loop.
def install_asyncio_exception_filter() -> None:
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()

    def handler(loop_obj, context):
        if _is_benign_windows_proactor_reset(context) or _is_benign_windows_overlapped_cancel(context):
            return
        if previous_handler is not None:
            previous_handler(loop_obj, context)
        else:
            loop_obj.default_exception_handler(context)

    loop.set_exception_handler(handler)


# Paint terminal text only when color is supported.
def paint(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"{code}{text}{Ansi.RESET}"


# Curated active sources, grouped by confidence and freshness.
SOURCES: Tuple[SourceSpec, ...] = (
    # Highest-confidence sources with explicit validation/update claims.
    SourceSpec(
        name="proxifly_http",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        ),
        scheme_hint="http",
        priority=10,
        max_items=4000,
    ),
    SourceSpec(
        name="proxifly_https",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt",
        ),
        scheme_hint="http",
        priority=10,
        max_items=3000,
    ),
    SourceSpec(
        name="proxifly_socks4",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
        ),
        scheme_hint="socks4",
        priority=10,
        max_items=2500,
    ),
    SourceSpec(
        name="proxifly_socks5",
        urls=(
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        ),
        scheme_hint="socks5",
        priority=10,
        max_items=2500,
    ),
    SourceSpec(
        name="monosans_http",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        ),
        scheme_hint="http",
        priority=10,
        max_items=2500,
    ),
    SourceSpec(
        name="monosans_socks4",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=10,
        max_items=1800,
    ),
    SourceSpec(
        name="monosans_socks5",
        urls=(
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=10,
        max_items=1800,
    ),
    SourceSpec(
        name="iplocate_http",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
        ),
        scheme_hint="http",
        priority=11,
        max_items=2500,
    ),
    SourceSpec(
        name="iplocate_https",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt",
        ),
        scheme_hint="http",
        priority=11,
        max_items=2200,
    ),
    SourceSpec(
        name="iplocate_socks4",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=11,
        max_items=1800,
    ),
    SourceSpec(
        name="iplocate_socks5",
        urls=(
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=11,
        max_items=1800,
    ),
    SourceSpec(
        name="vakhov_http",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/http.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
        ),
        scheme_hint="http",
        priority=12,
        max_items=2500,
    ),
    SourceSpec(
        name="vakhov_socks4",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/socks4.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=12,
        max_items=1800,
    ),
    SourceSpec(
        name="vakhov_socks5",
        urls=(
            "https://vakhov.github.io/fresh-proxy-list/socks5.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=12,
        max_items=1800,
    ),
    SourceSpec(
        name="fyvri_http",
        urls=(
            "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/http.txt",
        ),
        scheme_hint="http",
        priority=13,
        max_items=2200,
    ),
    SourceSpec(
        name="fyvri_socks4",
        urls=(
            "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=13,
        max_items=1600,
    ),
    SourceSpec(
        name="fyvri_socks5",
        urls=(
            "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=13,
        max_items=1600,
    ),
    SourceSpec(
        name="roosterkid_http",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        ),
        scheme_hint="http",
        priority=14,
        max_items=2200,
    ),
    SourceSpec(
        name="roosterkid_socks4",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        ),
        scheme_hint="socks4",
        priority=14,
        max_items=1600,
    ),
    SourceSpec(
        name="roosterkid_socks5",
        urls=(
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        ),
        scheme_hint="socks5",
        priority=14,
        max_items=1600,
    ),
    # Secondary active sources used as additional coverage.
    SourceSpec(
        name="r00tee_http",
        urls=(
            "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",
        ),
        scheme_hint="http",
        priority=20,
        max_items=2500,
    ),
    SourceSpec(
        name="r00tee_socks4",
        urls=(
            "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt",
        ),
        scheme_hint="socks4",
        priority=20,
        max_items=1800,
    ),
    SourceSpec(
        name="r00tee_socks5",
        urls=(
            "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",
        ),
        scheme_hint="socks5",
        priority=20,
        max_items=1800,
    ),
    SourceSpec(
        name="clearproxy_http",
        urls=(
            "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw/all.txt",
        ),
        scheme_hint="http",
        priority=21,
        max_items=2500,
    ),
    SourceSpec(
        name="clearproxy_socks4",
        urls=(
            "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks4/raw/all.txt",
        ),
        scheme_hint="socks4",
        priority=21,
        max_items=1800,
    ),
    SourceSpec(
        name="clearproxy_socks5",
        urls=(
            "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks5/raw/all.txt",
        ),
        scheme_hint="socks5",
        priority=21,
        max_items=1800,
    ),
    SourceSpec(
        name="vann_http",
        urls=(
            "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/http.txt",
        ),
        scheme_hint="http",
        priority=22,
        max_items=1800,
    ),
    SourceSpec(
        name="vann_socks4",
        urls=(
            "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=22,
        max_items=1200,
    ),
    SourceSpec(
        name="ercin_http",
        urls=(
            "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
        ),
        scheme_hint="http",
        priority=23,
        max_items=1800,
    ),
    SourceSpec(
        name="ercin_socks4",
        urls=(
            "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=23,
        max_items=1200,
    ),
    SourceSpec(
        name="ercin_socks5",
        urls=(
            "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=23,
        max_items=1200,
    ),
    SourceSpec(
        name="proxyscraper_http",
        urls=(
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",
        ),
        scheme_hint="http",
        priority=24,
        max_items=1800,
    ),
    SourceSpec(
        name="proxyscraper_socks4",
        urls=(
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=24,
        max_items=1200,
    ),
    SourceSpec(
        name="proxyscraper_socks5",
        urls=(
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=24,
        max_items=1200,
    ),
    SourceSpec(
        name="thespeedx_http",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        ),
        scheme_hint="http",
        priority=25,
        max_items=1800,
    ),
    SourceSpec(
        name="thespeedx_socks4",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=25,
        max_items=1200,
    ),
    SourceSpec(
        name="thespeedx_socks5",
        urls=(
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=25,
        max_items=1200,
    ),
    SourceSpec(
        name="zaeem_http",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
        ),
        scheme_hint="http",
        priority=22,
        max_items=1600,
    ),
    SourceSpec(
        name="zaeem_socks4",
        urls=(
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=22,
        max_items=1200,
    ),
    SourceSpec(
        name="aliilapro_http",
        urls=(
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
        ),
        scheme_hint="http",
        priority=23,
        max_items=1600,
    ),
    SourceSpec(
        name="aliilapro_socks4",
        urls=(
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=23,
        max_items=1200,
    ),
    SourceSpec(
        name="argh94_http",
        urls=(
            "https://raw.githubusercontent.com/Argh94/Proxy-List/main/HTTP.txt",
        ),
        scheme_hint="http",
        priority=24,
        max_items=1800,
    ),
    SourceSpec(
        name="argh94_socks4",
        urls=(
            "https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS4.txt",
        ),
        scheme_hint="socks4",
        priority=24,
        max_items=1200,
    ),
    SourceSpec(
        name="argh94_socks5",
        urls=(
            "https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS5.txt",
        ),
        scheme_hint="socks5",
        priority=24,
        max_items=1200,
    ),
    SourceSpec(
        name="vmheaven_http",
        urls=(
            "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/http.txt",
        ),
        scheme_hint="http",
        priority=25,
        max_items=1600,
    ),
    SourceSpec(
        name="vmheaven_socks4",
        urls=(
            "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=25,
        max_items=1200,
    ),
    SourceSpec(
        name="vmheaven_socks5",
        urls=(
            "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=25,
        max_items=1200,
    ),
    SourceSpec(
        name="shiftytr_http",
        urls=(
            "https://raw.githubusercontent.com/shiftytr/proxy-list/master/http.txt",
        ),
        scheme_hint="http",
        priority=26,
        max_items=2200,
    ),
    SourceSpec(
        name="shiftytr_https",
        urls=(
            "https://raw.githubusercontent.com/shiftytr/proxy-list/master/https.txt",
        ),
        scheme_hint="http",
        priority=26,
        max_items=1800,
    ),
    SourceSpec(
        name="shiftytr_socks4",
        urls=(
            "https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=26,
        max_items=1600,
    ),
    SourceSpec(
        name="shiftytr_socks5",
        urls=(
            "https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=26,
        max_items=1600,
    ),
    SourceSpec(
        name="firmfox_http",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/http.txt",
        ),
        scheme_hint="http",
        priority=26,
        max_items=2200,
    ),
    SourceSpec(
        name="firmfox_https",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/https.txt",
        ),
        scheme_hint="http",
        priority=26,
        max_items=2000,
    ),
    SourceSpec(
        name="firmfox_socks4",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=26,
        max_items=1700,
    ),
    SourceSpec(
        name="firmfox_socks5",
        urls=(
            "https://raw.githubusercontent.com/Firmfox/proxify/main/proxies/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=26,
        max_items=1700,
    ),
    SourceSpec(
        name="proxyscrape_api_http",
        urls=(
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=12000&country=all&ssl=all&anonymity=all",
        ),
        scheme_hint="http",
        priority=27,
        max_items=2800,
    ),
    SourceSpec(
        name="proxyscrape_api_socks4",
        urls=(
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=12000&country=all",
        ),
        scheme_hint="socks4",
        priority=27,
        max_items=2200,
    ),
    SourceSpec(
        name="proxyscrape_api_socks5",
        urls=(
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=12000&country=all",
        ),
        scheme_hint="socks5",
        priority=27,
        max_items=3200,
    ),
    SourceSpec(
        name="proxyspace_http",
        urls=(
            "https://proxyspace.pro/http.txt",
        ),
        scheme_hint="http",
        priority=28,
        max_items=2600,
    ),
    SourceSpec(
        name="proxyspace_https",
        urls=(
            "https://proxyspace.pro/https.txt",
        ),
        scheme_hint="http",
        priority=28,
        max_items=2000,
    ),
    SourceSpec(
        name="proxyspace_socks4",
        urls=(
            "https://proxyspace.pro/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=28,
        max_items=2200,
    ),
    SourceSpec(
        name="proxyspace_socks5",
        urls=(
            "https://proxyspace.pro/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=28,
        max_items=2600,
    ),
    SourceSpec(
        name="jetkai_http",
        urls=(
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        ),
        scheme_hint="http",
        priority=29,
        max_items=2400,
    ),
    SourceSpec(
        name="jetkai_socks4",
        urls=(
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
        ),
        scheme_hint="socks4",
        priority=29,
        max_items=1800,
    ),
    SourceSpec(
        name="jetkai_socks5",
        urls=(
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        ),
        scheme_hint="socks5",
        priority=29,
        max_items=1700,
    ),
    SourceSpec(
        name="rdavydov_http",
        urls=(
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
        ),
        scheme_hint="http",
        priority=30,
        max_items=2200,
    ),
    SourceSpec(
        name="rdavydov_http_anonymous",
        urls=(
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/http.txt",
        ),
        scheme_hint="http",
        priority=30,
        max_items=1600,
    ),
    SourceSpec(
        name="rdavydov_socks4",
        urls=(
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=30,
        max_items=1700,
    ),
    SourceSpec(
        name="rdavydov_socks5",
        urls=(
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=30,
        max_items=1700,
    ),
    SourceSpec(
        name="zevtyardt_http",
        urls=(
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
        ),
        scheme_hint="http",
        priority=31,
        max_items=2200,
    ),
    SourceSpec(
        name="zevtyardt_socks4",
        urls=(
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=31,
        max_items=1800,
    ),
    SourceSpec(
        name="zevtyardt_socks5",
        urls=(
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=31,
        max_items=1800,
    ),
    SourceSpec(
        name="b4rcode_http",
        urls=(
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
        ),
        scheme_hint="http",
        priority=31,
        max_items=2200,
    ),
    SourceSpec(
        name="b4rcode_socks4",
        urls=(
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
        ),
        scheme_hint="socks4",
        priority=31,
        max_items=1800,
    ),
    SourceSpec(
        name="b4rcode_socks5",
        urls=(
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
        ),
        scheme_hint="socks5",
        priority=31,
        max_items=1700,
    ),
    SourceSpec(
        name="mmpx12_http",
        urls=(
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        ),
        scheme_hint="http",
        priority=32,
        max_items=1600,
    ),
    SourceSpec(
        name="mmpx12_socks4",
        urls=(
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=32,
        max_items=1600,
    ),
    SourceSpec(
        name="mmpx12_socks5",
        urls=(
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=32,
        max_items=1500,
    ),
    SourceSpec(
        name="sunny9577_http",
        urls=(
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
        ),
        scheme_hint="http",
        priority=33,
        max_items=2000,
    ),
    SourceSpec(
        name="sunny9577_socks4",
        urls=(
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks4_proxies.txt",
        ),
        scheme_hint="socks4",
        priority=33,
        max_items=1400,
    ),
    SourceSpec(
        name="sunny9577_socks5",
        urls=(
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.txt",
        ),
        scheme_hint="socks5",
        priority=33,
        max_items=1400,
    ),
    SourceSpec(
        name="openproxylist_http",
        urls=(
            "https://api.openproxylist.xyz/http.txt",
        ),
        scheme_hint="http",
        priority=34,
        max_items=1800,
    ),
    SourceSpec(
        name="openproxylist_socks4",
        urls=(
            "https://api.openproxylist.xyz/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=34,
        max_items=1500,
    ),
    SourceSpec(
        name="openproxylist_socks5",
        urls=(
            "https://api.openproxylist.xyz/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=34,
        max_items=1500,
    ),
    SourceSpec(
        name="clarketm_http_raw",
        urls=(
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        ),
        scheme_hint="http",
        priority=35,
        max_items=1600,
    ),
    SourceSpec(
        name="hookzof_socks5",
        urls=(
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        ),
        scheme_hint="socks5",
        priority=30,
        max_items=1200,
    ),
    # Extra lower-priority public repositories for fallback coverage.
    SourceSpec(
        name="gfpcom_http",
        urls=(
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt",
        ),
        scheme_hint="http",
        priority=36,
        max_items=2500,
    ),
    SourceSpec(
        name="gfpcom_https",
        urls=(
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt",
        ),
        scheme_hint="http",
        priority=36,
        max_items=2200,
    ),
    SourceSpec(
        name="gfpcom_socks4",
        urls=(
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=36,
        max_items=2200,
    ),
    SourceSpec(
        name="gfpcom_socks5",
        urls=(
            "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=36,
        max_items=2200,
    ),
    SourceSpec(
        name="prxchk_http",
        urls=(
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
        ),
        scheme_hint="http",
        priority=37,
        max_items=1800,
    ),
    SourceSpec(
        name="prxchk_socks4",
        urls=(
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
        ),
        scheme_hint="socks4",
        priority=37,
        max_items=1400,
    ),
    SourceSpec(
        name="prxchk_socks5",
        urls=(
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
        ),
        scheme_hint="socks5",
        priority=37,
        max_items=1400,
    ),
    SourceSpec(
        name="casals_http",
        urls=(
            "https://raw.githubusercontent.com/casa-ls/proxy-list/main/http",
        ),
        scheme_hint="http",
        priority=39,
        max_items=2200,
    ),
    SourceSpec(
        name="casals_socks4",
        urls=(
            "https://raw.githubusercontent.com/casa-ls/proxy-list/main/socks4",
        ),
        scheme_hint="socks4",
        priority=39,
        max_items=1400,
    ),
    SourceSpec(
        name="casals_socks5",
        urls=(
            "https://raw.githubusercontent.com/casa-ls/proxy-list/main/socks5",
        ),
        scheme_hint="socks5",
        priority=39,
        max_items=1400,
    ),
)


# Make sure the current interpreter is new enough for asyncio features we use.
def _python_version_ok() -> bool:
    return sys.version_info >= (3, 8)


# Try a normal install first, then a user install as fallback.
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


# Import a dependency and auto-install it only when needed.
def _import_or_install(import_name: str, package_name: Optional[str] = None):
    try:
        return importlib.import_module(import_name)
    except Exception:
        package = package_name or import_name
        print(f"Installing missing dependency: {package}", file=sys.stderr)
        if not _try_install(package):
            raise RuntimeError(f"Missing dependency '{package}' and auto-install failed.")
        return importlib.import_module(import_name)


# Load all runtime network dependencies once.
def ensure_runtime_deps():
    aiohttp = _import_or_install("aiohttp")
    python_socks_asyncio = _import_or_install("python_socks.async_.asyncio", "python-socks")
    return aiohttp, python_socks_asyncio


# Raise the file descriptor limit when the platform allows it.
def maybe_raise_nofile_limit(expected_connections: int) -> None:
    try:
        import resource
    except Exception:
        return

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard == resource.RLIM_INFINITY:
            target = max(soft, min(65535, expected_connections * 3 + 1024))
        else:
            target = min(hard, max(soft, expected_connections * 3 + 1024))
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        return


# Normalize source schemes to the three proxy types we support.
def normalize_scheme(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower()
    if value == "https":
        return "http"
    if value in {"http", "socks4", "socks5"}:
        return value
    return None


# Add IPv6 brackets only when serializing host:port values.
def format_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


# Reject malformed dotted quads that would otherwise slip in as hostnames.
def normalize_host(host: str) -> Optional[str]:
    host = host.strip().strip("[]").lower().rstrip(".")
    if not host:
        return None

    if IPV4_LIKE_RE.fullmatch(host):
        parts = host.split(".")
        octets: List[str] = []
        for part in parts:
            value = int(part)
            if value > 255:
                return None
            octets.append(str(value))
        return ".".join(octets)

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if IPV4_LIKE_RE.fullmatch(host):
            return None
        return host if HOSTNAME_RE.fullmatch(host) else None


# Skip private, loopback, reserved, and otherwise non-routable IPs.
def is_global_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


# Accept only legal TCP port numbers.
def valid_port(value: str) -> Optional[int]:
    try:
        port = int(value)
    except Exception:
        return None
    return port if 1 <= port <= 65535 else None


# Remove wrappers and tiny punctuation noise around proxy tokens.
def strip_token(token: str) -> str:
    token = token.strip()
    token = token.strip('"\'`<>(){}')
    token = token.strip(",;")
    if not (token.startswith("[") and "]:" in token):
        token = token.strip("[]")
    return token.rstrip(".:")


# Parse host, port, and optional auth from raw input text.
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
        if not normalized_host or not is_global_host(normalized_host):
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
    if not normalized_host or port is None or not is_global_host(normalized_host):
        return None

    return normalized_host, port, username, password


# Parse one token into a normalized proxy candidate.
def parse_proxy_token(token: str, source: SourceSpec) -> Optional[ProxyCandidate]:
    token = strip_token(token)
    if not token or token.startswith("#"):
        return None

    scheme = source.scheme_hint
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
        source_name=source.name,
        source_priority=source.priority,
    )


# Try to extract either IPv4 or IPv6 from small JSON/text responses.
def extract_ip(text: str) -> Optional[str]:
    def try_one(value: str) -> Optional[str]:
        token = value.strip().strip('"\'[](){}<>,;')
        with suppress(ValueError):
            return str(ipaddress.ip_address(token))
        return None

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("ip", "origin", "query"):
                value = data.get(key)
                if isinstance(value, str):
                    for part in re.split(r"[\s,]+", value):
                        ip_text = try_one(part)
                        if ip_text:
                            return ip_text
    except Exception:
        pass

    for part in re.split(r"[\s,]+", text):
        ip_text = try_one(part)
        if ip_text:
            return ip_text
    return None


# Compute the effective parse cap for one source.
def source_item_limit(source: SourceSpec, per_source_limit: int) -> int:
    limit = source.max_items or per_source_limit
    if source.max_items and per_source_limit > 0:
        limit = min(source.max_items, per_source_limit)
    elif per_source_limit > 0:
        limit = per_source_limit
    if limit <= 0:
        limit = 1_000_000
    return limit


# Stream and parse a text source without loading the whole response into memory.
async def read_text_tokens(response, source: SourceSpec, per_source_limit: int) -> List[ProxyCandidate]:
    limit = source_item_limit(source, per_source_limit)

    found: List[ProxyCandidate] = []
    seen = set()
    buffer = ""

    async for chunk in response.content.iter_chunked(65536):
        buffer += chunk.decode("utf-8", errors="ignore")
        parts = TOKEN_SPLIT_RE.split(buffer)
        buffer = parts.pop() if parts else ""
        for token in parts:
            candidate = parse_proxy_token(token, source)
            if candidate is None:
                continue
            if candidate.key in seen:
                continue
            seen.add(candidate.key)
            found.append(candidate)
            if len(found) >= limit:
                return found

    if buffer:
        candidate = parse_proxy_token(buffer, source)
        if candidate is not None and candidate.key not in seen:
            found.append(candidate)

    return found[:limit]


# Parse only a small prefix used by source health checks.
def parse_sample_candidates(text: str, source: SourceSpec, target_count: int) -> int:
    if target_count <= 0:
        target_count = 1
    seen = set()
    hits = 0
    for token in TOKEN_SPLIT_RE.split(text):
        candidate = parse_proxy_token(token, source)
        if candidate is None or candidate.key in seen:
            continue
        seen.add(candidate.key)
        hits += 1
        if hits >= target_count:
            return hits
    return hits


# Try one URL quickly before full source download.
async def probe_source_url(
    session,
    source: SourceSpec,
    url: str,
    timeout_s: float,
    sample_bytes: int,
) -> Tuple[bool, Optional[str]]:
    timeout = max(0.8, timeout_s)
    bytes_to_read = max(1024, sample_bytes)
    headers = {"Range": f"bytes=0-{bytes_to_read - 1}"}
    try:
        async with session.get(url, allow_redirects=True, timeout=timeout, headers=headers) as response:
            if response.status >= 400:
                return False, f"HTTP {response.status}"
            sample = await response.content.read(bytes_to_read)
            if not sample:
                return False, "empty body"
            text = sample.decode("utf-8", errors="ignore")
            parsed = parse_sample_candidates(text, source, source.min_items)
            if parsed < source.min_items:
                return False, f"sample parsed {parsed}"
            return True, None
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return False, str(exc)


# Pick URL order so a healthy mirror is tried first.
def ordered_source_urls(source: SourceSpec, preferred_url: Optional[str] = None) -> Tuple[str, ...]:
    if not preferred_url or preferred_url not in source.urls:
        return source.urls
    return (preferred_url,) + tuple(url for url in source.urls if url != preferred_url)


# Fetch one source, trying every mirror until we get enough parsable data.
async def fetch_one_source(
    session,
    source: SourceSpec,
    per_source_limit: int,
    preferred_url: Optional[str] = None,
) -> Tuple[SourceResult, List[ProxyCandidate]]:
    last_error: Optional[str] = None
    for url in ordered_source_urls(source, preferred_url):
        try:
            async with session.get(url, allow_redirects=True) as response:
                if response.status >= 400:
                    last_error = f"HTTP {response.status}"
                    continue
                items = await read_text_tokens(response, source, per_source_limit)
                if len(items) < source.min_items:
                    last_error = f"parsed {len(items)} items"
                    continue
                return SourceResult(source=source, count=len(items), url_used=url, error=None), items
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_error = str(exc)
    return SourceResult(source=source, count=0, url_used=None, error=last_error or "download failed"), []


# Merge duplicates while keeping the higher-priority source metadata.
def merge_unique_candidates(candidates: Iterable[ProxyCandidate]) -> List[ProxyCandidate]:
    merged: Dict[Tuple[str, str, int, Optional[str], Optional[str]], ProxyCandidate] = {}
    for candidate in candidates:
        existing = merged.get(candidate.key)
        if existing is None or candidate.source_priority < existing.source_priority:
            merged[candidate.key] = candidate
    return list(merged.values())


# Interleave sources so one weak source cannot dominate the whole queue.
def order_candidates(candidates: Sequence[ProxyCandidate]) -> List[ProxyCandidate]:
    buckets: Dict[str, Dict[str, Deque[ProxyCandidate]]] = {
        scheme: defaultdict(deque) for scheme in SCHEME_ORDER
    }
    source_priority: Dict[str, int] = {}

    for candidate in sorted(
        candidates,
        key=lambda item: (item.source_priority, item.source_name, item.scheme, item.host, item.port),
    ):
        source_priority[candidate.source_name] = candidate.source_priority
        buckets[candidate.scheme][candidate.source_name].append(candidate)

    ordered_source_names = [
        name for name, _ in sorted(source_priority.items(), key=lambda item: (item[1], item[0]))
    ]

    ordered: List[ProxyCandidate] = []
    for scheme in SCHEME_ORDER:
        active = [name for name in ordered_source_names if buckets[scheme].get(name)]
        while active:
            next_active: List[str] = []
            for name in active:
                bucket = buckets[scheme][name]
                if not bucket:
                    continue
                ordered.append(bucket.popleft())
                if bucket:
                    next_active.append(name)
            active = next_active
    return ordered


# Build parsed targets once for all workers.
def expected_probe_status(split) -> Optional[int]:
    if (split.path or "").rstrip("/") == "/generate_204":
        return 204
    return None


def build_probe_targets(urls: Sequence[str]) -> List[ProbeTarget]:
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


# Fetch sources in priority batches so fast sources start earlier.
async def fetch_all_sources(args) -> Tuple[List[ProxyCandidate], List[SourceResult]]:
    aiohttp, _ = ensure_runtime_deps()
    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=max(5.0, args.source_timeout))
    connector = aiohttp.TCPConnector(
        limit=0,
        ttl_dns_cache=300,
        enable_cleanup_closed=_connector_cleanup_closed_enabled(),
    )

    candidate_goal = max(1000, args.need * DEFAULT_CANDIDATE_MULTIPLIER)
    per_source_limit = args.per_source_limit
    ordered_sources = sorted(SOURCES, key=lambda item: (item.priority, item.name))

    merged_candidates: Dict[Tuple[str, str, int, Optional[str], Optional[str]], ProxyCandidate] = {}
    results: List[SourceResult] = []
    preferred_urls: Dict[str, str] = {}

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=headers,
        trust_env=False,
    ) as session:
        if not args.skip_source_health_check:
            health_semaphore = asyncio.Semaphore(max(1, args.source_workers))

            async def bounded_health(source: SourceSpec):
                async with health_semaphore:
                    last_error: Optional[str] = None
                    for url in source.urls:
                        ok, error = await probe_source_url(
                            session=session,
                            source=source,
                            url=url,
                            timeout_s=args.source_health_timeout,
                            sample_bytes=args.source_health_bytes,
                        )
                        if ok:
                            return source, url, None
                        last_error = error
                    return source, None, last_error or "health check failed"

            health_rows = await asyncio.gather(
                *(bounded_health(source) for source in ordered_sources),
                return_exceptions=True,
            )

            healthy_sources: List[SourceSpec] = []
            for source, row in zip(ordered_sources, health_rows):
                if isinstance(row, Exception):
                    results.append(SourceResult(source=source, count=0, error=f"health: {row}"))
                    continue
                _, preferred_url, error = row
                if not preferred_url:
                    results.append(SourceResult(source=source, count=0, error=f"health: {error}"))
                    continue
                preferred_urls[source.name] = preferred_url
                healthy_sources.append(source)
            ordered_sources = healthy_sources

        for start in range(0, len(ordered_sources), max(1, args.source_batch_size)):
            batch = ordered_sources[start : start + max(1, args.source_batch_size)]
            semaphore = asyncio.Semaphore(max(1, min(args.source_workers, len(batch))))

            async def bounded_fetch(source: SourceSpec):
                async with semaphore:
                    return await fetch_one_source(
                        session=session,
                        source=source,
                        per_source_limit=per_source_limit,
                        preferred_url=preferred_urls.get(source.name),
                    )

            gathered = await asyncio.gather(
                *(bounded_fetch(source) for source in batch),
                return_exceptions=True,
            )

            for source, item in zip(batch, gathered):
                if isinstance(item, Exception):
                    results.append(SourceResult(source=source, count=0, error=str(item)))
                    continue
                result, items = item
                results.append(result)
                for candidate in items:
                    existing = merged_candidates.get(candidate.key)
                    if existing is None or candidate.source_priority < existing.source_priority:
                        merged_candidates[candidate.key] = candidate

            if len(merged_candidates) >= candidate_goal:
                break

    return order_candidates(list(merged_candidates.values())), results


class ResultWriter:
    """Write one proxy per line with immediate flush but without expensive fsync."""

    def __init__(self, path: str):
        self.path = path
        self.handle = None
        self.written = set()

    def __enter__(self):
        output_path = Path(self.path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("", encoding="utf-8")
        self.written.clear()
        self.handle = output_path.open("a", encoding="utf-8", buffering=1, newline="\n")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handle is not None:
            self.handle.close()

    def write_line(self, line: str) -> bool:
        if self.handle is None:
            raise RuntimeError("Writer is not open.")
        if line in self.written:
            return False
        self.written.add(line)
        self.handle.write(line + "\n")
        self.handle.flush()
        return True


class SharedState:
    """Track global worker counters and stop conditions."""

    def __init__(self, need: int):
        self.need = need
        self.tested = 0
        self.found = 0
        self.active = 0
        self.recent_tests: Deque[float] = deque(maxlen=512)
        self.seen_working = set()
        self.stop_event = asyncio.Event()
        self.save_lock = asyncio.Lock()
        self.started_at = time.time()


# Read only a tiny direct HTTP response payload.
async def read_small_text(response, limit: int = 2048) -> str:
    data = await response.content.read(limit)
    return data.decode("utf-8", errors="ignore")


# Detect the direct public IP to support strict IP-change mode.
async def fetch_direct_ip(http_session, ip_url: str) -> Optional[str]:
    try:
        async with http_session.get(ip_url, allow_redirects=True) as response:
            if response.status >= 400:
                return None
            return extract_ip(await read_small_text(response, limit=4096))
    except Exception:
        return None


# Create an SSL context for tunnel checks.
def build_tls_context(verify_tls: bool) -> ssl.SSLContext:
    if verify_tls:
        return ssl.create_default_context()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


# Close an asyncio writer quietly in all supported Python versions.
async def close_writer(writer) -> None:
    if writer is None:
        return
    with suppress(Exception):
        writer.close()
    wait_closed = getattr(writer, "wait_closed", None)
    if wait_closed is not None:
        with suppress(Exception, asyncio.TimeoutError):
            await asyncio.wait_for(wait_closed(), timeout=WRITER_CLOSE_TIMEOUT)


# Return the remaining wall-clock budget for one in-flight network step.
def seconds_left(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


# Read the status line, headers, and an optional small body from a raw HTTP stream.
async def read_http_response(reader, deadline: float, body_limit: int = 0) -> Tuple[Optional[int], str]:
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


def http_proxy_target_url(target: ProbeTarget) -> str:
    """Build the absolute-form URL required by plain HTTP proxy requests."""
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


async def request_via_plain_http_proxy(
    candidate: ProxyCandidate,
    target: ProbeTarget,
    deadline: float,
    body_limit: int = 0,
) -> Tuple[bool, Optional[str]]:
    """Check HTTP proxies using normal absolute-form HTTP requests."""
    writer = None
    try:
        remaining = seconds_left(deadline)
        if remaining <= 0:
            return False, None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(candidate.host, candidate.port),
            timeout=remaining,
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


# Send one lightweight HTTP request through a proxy tunnel.
async def request_via_proxy(
    AsyncProxy,
    candidate: ProxyCandidate,
    target: ProbeTarget,
    deadline: float,
    tls_context: ssl.SSLContext,
    body_limit: int = 0,
) -> Tuple[bool, Optional[str]]:
    sock = None
    writer = None

    if candidate.scheme == "http" and target.scheme == "http":
        return await request_via_plain_http_proxy(
            candidate=candidate,
            target=target,
            deadline=deadline,
            body_limit=body_limit,
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


# Keep the main reachability probe bounded so the final tail does not stall.
def probe_deadline(timeout_s: float) -> float:
    return time.monotonic() + max(0.35, timeout_s + PROBE_DEADLINE_GRACE)


# Give strict IP validation its own short budget after reachability succeeds.
def ip_check_deadline(timeout_s: float) -> float:
    return time.monotonic() + max(0.5, min(timeout_s + PROBE_DEADLINE_GRACE, STRICT_IP_TIMEOUT_CAP))


# Bound every candidate with one hard deadline so late-stage workers cannot hang.
def candidate_hard_timeout(args) -> float:
    rounds = max(1, int(getattr(args, "stability_checks", 1)))
    reachability_budget = rounds * max(0.35, float(args.timeout) + PROBE_DEADLINE_GRACE)
    ip_budget = 0.0
    if getattr(args, "require_different_ip", False):
        ip_budget = max(0.5, min(float(args.timeout) + PROBE_DEADLINE_GRACE, STRICT_IP_TIMEOUT_CAP))
    return max(0.8, reachability_budget + ip_budget + 0.25)


# Probe multiple small URLs at once and stop on the first success.
async def probe_reachability(
    AsyncProxy,
    candidate: ProxyCandidate,
    targets: Sequence[ProbeTarget],
    tls_context: ssl.SSLContext,
    timeout_s: float,
) -> bool:
    deadline = probe_deadline(timeout_s)

    # Windows Proactor loop can emit overlapped-cancel noise when many pending
    # probe tasks are cancelled. Sequential probing is slower but far more stable.
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
                pending,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
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
                                asyncio.gather(*pending, return_exceptions=True),
                                timeout=0.3,
                            )
                    return True
        return False
    finally:
        leftovers = [task for task in tasks if not task.done()]
        for task in leftovers:
            task.cancel()
        if leftovers:
            with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(
                    asyncio.gather(*leftovers, return_exceptions=True),
                    timeout=0.3,
                )


# Check one proxy against one or more small probe URLs.
async def test_candidate(AsyncProxy, candidate: ProxyCandidate, args, baseline_ip: Optional[str], tls_context) -> bool:
    rounds = max(1, int(args.stability_checks))
    for idx in range(rounds):
        round_timeout = args.timeout
        if idx > 0:
            round_timeout = max(0.35, args.timeout * args.stability_timeout_factor)
        if not await probe_reachability(
            AsyncProxy=AsyncProxy,
            candidate=candidate,
            targets=args.probe_targets,
            tls_context=tls_context,
            timeout_s=round_timeout,
        ):
            return False

    if args.require_different_ip:
        if not baseline_ip:
            return False
        ok, text = await request_via_proxy(
            AsyncProxy=AsyncProxy,
            candidate=candidate,
            target=args.ip_target,
            deadline=ip_check_deadline(args.timeout),
            tls_context=tls_context,
            body_limit=4096,
        )
        if not ok or not text:
            return False
        observed_ip = extract_ip(text)
        if not observed_ip or observed_ip == baseline_ip:
            return False

    return True


# Compute a short sliding-window rate so the live number stays truthful near the end.
def recent_rate(samples: Deque[float], window: float = RECENT_RATE_WINDOW) -> float:
    now = time.monotonic()
    while samples and now - samples[0] > window:
        samples.popleft()
    if not samples:
        return 0.0
    span = max(0.25, min(window, now - samples[0]))
    return len(samples) / span


# Compose a compact live progress line for the terminal.
def status_line(state: SharedState, total: int) -> str:
    rate = recent_rate(state.recent_tests)
    tested_text = paint(f"Tested {state.tested}/{total}", Ansi.CYAN)
    working_text = paint(f"working={state.found}", Ansi.GREEN if state.found > 0 else Ansi.DIM)
    need_text = paint(f"need={state.need}", Ansi.YELLOW)
    rate_text = paint(f"rate={rate:.1f}/s", Ansi.MAGENTA)
    active_text = paint(f"active={state.active}", Ansi.BLUE if state.active > 0 else Ansi.DIM)
    return f"{tested_text} | {working_text} | {need_text} | {rate_text} | {active_text}"


# Refresh the status line until workers finish.
async def progress_loop(state: SharedState, total: int) -> None:
    while not state.stop_event.is_set():
        line = status_line(state, total)
        print("\r" + line + " " * 10, end="", file=sys.stderr, flush=True)
        await asyncio.sleep(0.25)


async def empty_queue_tail_watch(
    state: SharedState,
    queue: "asyncio.Queue[ProxyCandidate]",
    tail_timeout_s: float,
) -> None:
    """Stop the run when only the slow final stragglers remain."""
    if tail_timeout_s <= 0:
        return

    empty_since: Optional[float] = None
    while not state.stop_event.is_set():
        if queue.empty():
            if state.active <= 0:
                return
            if empty_since is None:
                empty_since = time.monotonic()
            elif time.monotonic() - empty_since >= tail_timeout_s:
                state.stop_event.set()
                return
        else:
            empty_since = None
        await asyncio.sleep(0.05)


# Pull one candidate at a time from the queue and test it.
async def worker_loop(
    state: SharedState,
    queue: "asyncio.Queue[ProxyCandidate]",
    AsyncProxy,
    args,
    baseline_ip: Optional[str],
    tls_context: ssl.SSLContext,
    writer: ResultWriter,
    hard_timeout_s: float,
) -> None:
    while not state.stop_event.is_set():
        try:
            candidate = queue.get_nowait()
        except asyncio.QueueEmpty:
            return

        state.active += 1

        try:
            ok = await asyncio.wait_for(
                test_candidate(AsyncProxy, candidate, args, baseline_ip, tls_context),
                timeout=hard_timeout_s,
            )
        except asyncio.CancelledError:
            state.active = max(0, state.active - 1)
            raise
        except Exception:
            ok = False

        state.active = max(0, state.active - 1)
        state.tested += 1
        state.recent_tests.append(time.monotonic())
        if not ok:
            continue

        proxy_url = candidate.proxy_url
        async with state.save_lock:
            if proxy_url in state.seen_working:
                continue
            if state.found >= state.need:
                state.stop_event.set()
                return
            wrote = writer.write_line(proxy_url)
            state.seen_working.add(proxy_url)
            if not wrote:
                continue

            state.found += 1
            if state.found >= state.need:
                state.stop_event.set()
                return


# Run the full proxy-checking worker pool and stop once enough proxies are found.
async def run_checks(candidates: Sequence[ProxyCandidate], args) -> Tuple[int, int, float, Optional[str]]:
    aiohttp, python_socks_asyncio = ensure_runtime_deps()
    AsyncProxy = python_socks_asyncio.Proxy

    maybe_raise_nofile_limit(args.workers)

    timeout = aiohttp.ClientTimeout(total=max(0.5, args.timeout))
    connector = aiohttp.TCPConnector(
        limit=0,
        ttl_dns_cache=300,
        enable_cleanup_closed=_connector_cleanup_closed_enabled(),
    )
    headers = {"User-Agent": USER_AGENT}
    state = SharedState(need=args.need)
    tls_context = build_tls_context(args.verify_tls)

    queue: "asyncio.Queue[ProxyCandidate]" = asyncio.Queue()
    for candidate in candidates:
        queue.put_nowait(candidate)

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

            hard_timeout_s = candidate_hard_timeout(args)
            worker_count = max(1, min(args.workers, len(candidates)))
            progress_task = asyncio.create_task(progress_loop(state, len(candidates)))
            empty_tail_task = asyncio.create_task(
                empty_queue_tail_watch(state, queue, args.tail_empty_timeout)
            )
            workers = [
                asyncio.create_task(
                    worker_loop(
                        state,
                        queue,
                        AsyncProxy,
                        args,
                        baseline_ip,
                        tls_context,
                        writer,
                        hard_timeout_s,
                    )
                )
                for _ in range(worker_count)
            ]
            gather_future = asyncio.gather(*workers, return_exceptions=True)
            stop_waiter = asyncio.create_task(state.stop_event.wait())

            try:
                done, _ = await asyncio.wait(
                    {gather_future, stop_waiter},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if stop_waiter in done and not gather_future.done():
                    # Two-phase tail shutdown: tiny grace period then hard cancel.
                    grace = min(0.2, max(0.05, args.tail_drain_timeout * 0.25))
                    with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                        await asyncio.wait_for(
                            gather_future,
                            timeout=grace,
                        )
                    if not gather_future.done():
                        for task in workers:
                            task.cancel()
                        with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                            await asyncio.wait_for(
                                asyncio.gather(*workers, return_exceptions=True),
                                timeout=args.tail_drain_timeout,
                            )
                else:
                    state.stop_event.set()
                    await gather_future
            finally:
                state.stop_event.set()
                if not stop_waiter.done():
                    stop_waiter.cancel()
                    await asyncio.gather(stop_waiter, return_exceptions=True)
                if not empty_tail_task.done():
                    empty_tail_task.cancel()
                    await asyncio.gather(empty_tail_task, return_exceptions=True)
                if not gather_future.done():
                    for task in workers:
                        task.cancel()
                    with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                        await asyncio.wait_for(
                            asyncio.gather(*workers, return_exceptions=True),
                            timeout=max(0.2, args.tail_drain_timeout),
                        )
                state.active = 0
                state.stop_event.set()
                with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(progress_task, timeout=0.5)
                if not progress_task.done():
                    progress_task.cancel()
                    await asyncio.gather(progress_task, return_exceptions=True)
                print("\r" + status_line(state, len(candidates)) + " " * 10, file=sys.stderr, flush=True)

    elapsed = time.time() - state.started_at
    return state.tested, state.found, elapsed, baseline_ip


# Ask interactively only when stdin is a terminal and --need was not passed.
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


# Keep source parsing aggressive enough without downloading everything.
def auto_per_source_limit(need: int) -> int:
    return min(6000, max(1200, need * 45))


# Print a short fetch summary plus the strongest source counts.
def print_source_summary(results: Iterable[SourceResult], total_unique: int) -> None:
    rows = list(results)
    ok_rows = [item for item in rows if not item.error and item.count > 0]
    failed_rows = [item for item in rows if item.error]
    print(
        f"{paint('Fetched sources', Ansi.BLUE)}: {len(ok_rows)}/{len(rows)} | "
        f"{paint('unique candidates', Ansi.CYAN)}: {total_unique:,}",
        file=sys.stderr,
    )
    if ok_rows:
        top = ", ".join(
            f"{item.source.name}={item.count}"
            for item in sorted(ok_rows, key=lambda row: row.count, reverse=True)[:6]
        )
        print(f"top sources: {top}", file=sys.stderr)
    if failed_rows:
        failed_preview = ", ".join(item.source.name for item in failed_rows[:10])
        more = ""
        if len(failed_rows) > 10:
            more = f", +{len(failed_rows) - 10} more"
        print(f"failed/skipped ({len(failed_rows)}): {failed_preview}{more}", file=sys.stderr)


# Print the built-in source catalog and exit.
def list_sources() -> None:
    for item in sorted(SOURCES, key=lambda source: (source.priority, source.name)):
        print(f"{item.priority}\t{item.name}\t{item.scheme_hint}\t{item.urls[0]}")


# Build the CLI parser.
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Fetch public proxies from curated public sources and save working ones to one file."
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
        help=f"Per-proxy timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    ap.add_argument(
        "--stability-checks",
        type=int,
        default=DEFAULT_STABILITY_CHECKS,
        help=f"How many successful reachability rounds a proxy must pass (default: {DEFAULT_STABILITY_CHECKS}).",
    )
    ap.add_argument(
        "--stability-timeout-factor",
        type=float,
        default=DEFAULT_STABILITY_TIMEOUT_FACTOR,
        help=(
            "Timeout multiplier used for extra stability rounds after the first success "
            f"(default: {DEFAULT_STABILITY_TIMEOUT_FACTOR})."
        ),
    )
    ap.add_argument(
        "--tail-drain-timeout",
        type=float,
        default=DEFAULT_TAIL_DRAIN_TIMEOUT,
        help=(
            "Max seconds to wait for worker cancellation after stop condition is reached "
            f"(default: {DEFAULT_TAIL_DRAIN_TIMEOUT})."
        ),
    )
    ap.add_argument(
        "--tail-empty-timeout",
        type=float,
        default=DEFAULT_TAIL_EMPTY_TIMEOUT,
        help=(
            "Optional seconds to keep the last active checks after the candidate queue is empty. "
            "0 waits for every candidate "
            f"(default: {DEFAULT_TAIL_EMPTY_TIMEOUT})."
        ),
    )
    ap.add_argument(
        "--test-url",
        action="append",
        dest="test_urls",
        default=None,
        help="Probe URL used to verify proxy reachability. Can be passed multiple times.",
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
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates during proxy checks. Off by default for reachability speed.",
    )
    ap.add_argument(
        "--source-timeout",
        type=float,
        default=DEFAULT_SOURCE_TIMEOUT,
        help=f"Timeout for source downloads (default: {DEFAULT_SOURCE_TIMEOUT}).",
    )
    ap.add_argument(
        "--source-health-timeout",
        type=float,
        default=DEFAULT_SOURCE_HEALTH_TIMEOUT,
        help=f"Timeout for source health pre-check requests (default: {DEFAULT_SOURCE_HEALTH_TIMEOUT}).",
    )
    ap.add_argument(
        "--source-health-bytes",
        type=int,
        default=DEFAULT_SOURCE_HEALTH_BYTES,
        help=f"How many bytes to sample while validating each source (default: {DEFAULT_SOURCE_HEALTH_BYTES}).",
    )
    ap.add_argument(
        "--source-workers",
        type=int,
        default=DEFAULT_SOURCE_WORKERS,
        help=f"Concurrent source downloads inside one batch (default: {DEFAULT_SOURCE_WORKERS}).",
    )
    ap.add_argument(
        "--source-batch-size",
        type=int,
        default=DEFAULT_SOURCE_BATCH_SIZE,
        help=f"How many sources to fetch before re-evaluating candidate count (default: {DEFAULT_SOURCE_BATCH_SIZE}).",
    )
    ap.add_argument(
        "--per-source-limit",
        type=int,
        default=DEFAULT_PER_SOURCE_LIMIT,
        help="Max parsed proxies per source. 0 = automatic.",
    )
    ap.add_argument(
        "--skip-source-health-check",
        action="store_true",
        help="Skip lightweight source health checks before full downloads.",
    )
    ap.add_argument(
        "--list-sources",
        action="store_true",
        help="Print built-in curated sources and exit.",
    )
    return ap


# Run source fetching first, then proxy testing.
async def async_main(args) -> int:
    install_asyncio_exception_filter()
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
        "tested={tested:,} | workers={workers} | timeout={timeout}s | "
        "stability_checks={stability} | elapsed={elapsed:.2f}s".format(
            tested=tested,
            workers=args.workers,
            timeout=args.timeout,
            stability=args.stability_checks,
            elapsed=elapsed,
        ),
        file=sys.stderr,
    )
    if baseline_ip:
        print(f"baseline_ip={baseline_ip}", file=sys.stderr)
    if found < args.need:
        if tested >= len(candidates):
            print(
                paint(
                    f"Warning: only {found} working proxies were found after checking all {len(candidates):,} candidates.",
                    Ansi.YELLOW,
                ),
                file=sys.stderr,
            )
        else:
            print(
                paint(
                    f"Warning: stopped after {tested:,}/{len(candidates):,} candidates. "
                    "Use --tail-empty-timeout 0 for a complete check.",
                    Ansi.YELLOW,
                ),
                file=sys.stderr,
            )
    return 0


# Parse CLI input, apply defaults, and launch the async entry point.
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
    args.stability_checks = max(1, int(args.stability_checks))
    args.stability_timeout_factor = min(1.0, max(0.2, float(args.stability_timeout_factor)))
    args.tail_drain_timeout = max(0.2, min(5.0, float(args.tail_drain_timeout)))
    args.tail_empty_timeout = max(0.0, min(30.0, float(args.tail_empty_timeout)))
    args.source_timeout = max(1.0, float(args.source_timeout))
    args.source_health_timeout = max(0.8, min(args.source_timeout, float(args.source_health_timeout)))
    args.source_health_bytes = max(1024, int(args.source_health_bytes))
    args.source_workers = max(1, int(args.source_workers))
    args.source_batch_size = max(1, int(args.source_batch_size))
    args.per_source_limit = int(args.per_source_limit)
    if args.per_source_limit <= 0:
        args.per_source_limit = auto_per_source_limit(args.need)

    try:
        args.probe_targets = build_probe_targets(args.test_urls or list(DEFAULT_TEST_URLS))
        args.ip_target = build_probe_targets([args.ip_url])[0]
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted. Saved results remain in the output file.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
