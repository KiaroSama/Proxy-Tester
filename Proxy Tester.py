#!/usr/bin/env python3
"""
Fetch public proxies from many GitHub-backed sources, test them on the current
machine/network, and save working proxies into one mixed output file.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from importlib import invalidate_caches
from importlib.util import find_spec
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote, urlsplit

USER_AGENT = "proxy-tester/9.0"
DEFAULT_NEED = 50
DEFAULT_WORKERS = 1000
DEFAULT_TIMEOUT = 3.0
DEFAULT_SOURCE_TIMEOUT = 12.0
DEFAULT_SOURCE_WORKERS = 32
DEFAULT_PER_SOURCE_LIMIT = 12000
DEFAULT_TEST_URL = "https://ec.europa.eu/taxation_customs/vies/"
DEFAULT_IP_URL = "https://api.ipify.org?format=json"
SCHEMES = ("http", "socks5", "socks4")
TOKEN_RE = re.compile(r"[^\s,;]+")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

REQUESTS = None

SOURCES: Sequence[Tuple[str, Sequence[str], Optional[str], int]] = (
    ("proxifly_http", ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",), "http", 12000),
    ("proxifly_socks4", ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",), "socks4", 12000),
    ("proxifly_socks5", ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",), "socks5", 12000),
    ("speedx_http", ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"), "http", 12000),
    ("speedx_socks4", ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt"), "socks4", 12000),
    ("speedx_socks5", ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"), "socks5", 12000),
    ("mishakorzik_all", ("https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/proxy.txt", "https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/packages/Proxy.txt"), None, 10000),
    ("monosans_http", ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",), "http", 12000),
    ("monosans_socks4", ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",), "socks4", 12000),
    ("monosans_socks5", ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",), "socks5", 12000),
    ("roosterkid_all", ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",), None, 10000),
    ("zaeem_http", ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt"), "http", 8000),
    ("zaeem_socks4", ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",), "socks4", 8000),
    ("zaeem_socks5", ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",), "socks5", 8000),
    ("vakhov_http", ("https://vakhov.github.io/fresh-proxy-list/http.txt", "https://vakhov.github.io/fresh-proxy-list/https.txt"), "http", 8000),
    ("vakhov_socks4", ("https://vakhov.github.io/fresh-proxy-list/socks4.txt",), "socks4", 8000),
    ("vakhov_socks5", ("https://vakhov.github.io/fresh-proxy-list/socks5.txt",), "socks5", 8000),
    ("clarketm_http", ("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",), "http", 10000),
    ("thenasty_http", ("https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/types/http/proxies.txt",), "http", 8000),
    ("thenasty_socks4", ("https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/types/socks4/proxies.txt",), "socks4", 8000),
    ("thenasty_socks5", ("https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/types/socks5/proxies.txt",), "socks5", 8000),
    ("thenasty_all", ("https://raw.githubusercontent.com/thenasty1337/free-proxy-list/main/data/latest/proxies.txt",), None, 10000),
    ("proxyscraper_http", ("https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",), "http", 8000),
    ("proxyscraper_socks4", ("https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt",), "socks4", 8000),
    ("proxyscraper_socks5", ("https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",), "socks5", 8000),
    ("r00tee_http", ("https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",), "http", 8000),
    ("r00tee_socks4", ("https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt",), "socks4", 8000),
    ("r00tee_socks5", ("https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",), "socks5", 8000),
    ("dpangestuw_http", ("https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt",), "http", 10000),
    ("dpangestuw_socks4", ("https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt",), "socks4", 10000),
    ("dpangestuw_socks5", ("https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",), "socks5", 10000),
    ("dpangestuw_all", ("https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/allive.txt",), None, 12000),
    ("kangproxy_all", ("https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",), None, 12000),
)


class C:
    R="\033[0m";B="\033[1m";D="\033[2m";R1="\033[31m";G="\033[32m";Y="\033[33m";B1="\033[34m";M="\033[35m";C1="\033[36m"

USE_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def color(text: str, code: str) -> str:
    return f"{code}{text}{C.R}" if USE_COLOR else text


def enable_windows_color() -> None:
    global USE_COLOR
    if sys.platform != "win32":
        return
    try:
        from colorama import just_fix_windows_console  # type: ignore
        just_fix_windows_console()
        USE_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
    except Exception:
        pass


def module_ok(name: str) -> bool:
    try:
        return find_spec(name) is not None
    except Exception:
        return False


def install(pkgs: Sequence[str]) -> bool:
    cmds = (
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *pkgs],
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--user", *pkgs],
    )
    for cmd in cmds:
        try:
            subprocess.check_call(cmd)
            return True
        except Exception:
            pass
    return False


def ensure_deps():
    global REQUESTS
    missing = []
    if not module_ok("requests"):
        missing.append("requests")
    if not module_ok("socks"):
        missing.append("PySocks")
    if sys.platform == "win32" and not module_ok("colorama"):
        missing.append("colorama")
    if missing:
        print("Installing missing dependencies: " + ", ".join(missing), file=sys.stderr, flush=True)
        if not install(missing):
            raise SystemExit("ERROR: failed to install runtime dependencies automatically.")
        invalidate_caches()
    import requests  # type: ignore
    REQUESTS = requests
    enable_windows_color()
    return requests


def strip_token(text: str) -> str:
    text = text.strip().strip('"\'`<>(){}').strip(',;')
    if not (text.startswith('[') and ']:' in text):
        text = text.strip('[]')
    return text.rstrip('.:')


def normalize_host(host: str) -> Optional[str]:
    host = host.strip().strip('[]').lower()
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except Exception:
        return host if HOST_RE.fullmatch(host) else None


def parse_proxy_token(token: str, fallback: Optional[str]):
    token = strip_token(token)
    if not token or token.startswith('#'):
        return None
    scheme = fallback
    if token.startswith('//'):
        token = 'http:' + token
    if '://' in token:
        parts = urlsplit(token)
        scheme = parts.scheme.lower().replace('https', 'http') if parts.scheme else fallback
        try:
            host, port = parts.hostname, parts.port
        except Exception:
            return None
        if not host or port is None:
            return None
        host = normalize_host(host)
        if not host:
            return None
        user = parts.username
        pwd = parts.password
    else:
        user = pwd = None
        hostpart = token
        if '@' in hostpart:
            auth, hostpart = hostpart.rsplit('@', 1)
            if ':' in auth:
                user, pwd = auth.split(':', 1)
            else:
                user = auth
        if hostpart.startswith('[') and ']:' in hostpart:
            host, port_s = hostpart[1:].split(']:', 1)
        else:
            if ':' not in hostpart:
                return None
            host, port_s = hostpart.rsplit(':', 1)
        try:
            port = int(port_s)
        except Exception:
            return None
        if not (1 <= port <= 65535):
            return None
        host = normalize_host(host)
        if not host:
            return None
    return scheme if scheme in SCHEMES else None, (host, port, user, pwd)


def proxy_url(parts: Tuple[str, int, Optional[str], Optional[str]], scheme: str) -> str:
    host, port, user, pwd = parts
    auth = ""
    if user is not None:
        auth = quote(user, safe="")
        if pwd is not None:
            auth += ":" + quote(pwd, safe="")
        auth += "@"
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'
    return f"{scheme}://{auth}{host}:{port}"


def scheme_order(hints: Set[str]) -> List[str]:
    out = [s for s in SCHEMES if s in hints]
    out.extend([s for s in SCHEMES if s not in out])
    return out


def extract_ip(text: str) -> Optional[str]:
    try:
        data = json.loads(text)
        for key in ("ip", "origin"):
            val = data.get(key)
            if isinstance(val, str):
                for part in [p.strip() for p in val.split(',') if p.strip()]:
                    if IP_RE.fullmatch(part):
                        return part
    except Exception:
        pass
    m = IP_RE.search(text or "")
    return m.group(0) if m else None


def download_text(urls: Sequence[str], timeout_s: float) -> str:
    requests = ensure_deps()
    last = None
    for url in urls:
        try:
            r = requests.get(url, timeout=timeout_s, headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            r.encoding = r.encoding or 'utf-8'
            return r.text
        except Exception as exc:
            last = exc
    raise RuntimeError(str(last) if last else 'download failed')


def fetch_one_source(spec, per_source_limit: int):
    name, urls, hint, max_items = spec
    limit = min(per_source_limit, max_items)
    try:
        text = download_text(urls, DEFAULT_SOURCE_TIMEOUT)
        found = []
        seen = set()
        for token in TOKEN_RE.findall(text):
            parsed = parse_proxy_token(token, hint)
            if not parsed:
                continue
            scheme_hint, key = parsed
            if key in seen:
                continue
            seen.add(key)
            found.append((key, {scheme_hint} if scheme_hint else set(), {name}))
            if len(found) >= limit:
                break
        return name, found, None
    except Exception as exc:
        return name, [], str(exc)


def fetch_all_sources(per_source_limit: int, source_workers: int, status) -> List[Tuple[Tuple[str, int, Optional[str], Optional[str]], Set[str], Set[str]]]:
    merged: Dict[Tuple[str, int, Optional[str], Optional[str]], Tuple[Set[str], Set[str]]] = {}
    done = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, source_workers)) as ex:
        futures = [ex.submit(fetch_one_source, spec, per_source_limit) for spec in SOURCES]
        for fut in cf.as_completed(futures):
            name, items, err = fut.result()
            for key, hints, sources in items:
                if key not in merged:
                    merged[key] = (set(hints), set(sources))
                else:
                    merged[key][0].update(hints)
                    merged[key][1].update(sources)
            done += 1
            status.show(f"Fetched sources: {done}/{len(SOURCES)} | unique candidates: {color(f'{len(merged):,}', C.C1)}")
    status.clear()
    ordered = []
    for key, (hints, sources) in merged.items():
        ordered.append((key, hints, sources))
    ordered.sort(key=lambda x: (-len(x[1]), -len(x[2]), x[0][0], x[0][1]))
    return ordered


def req_proxy_url(url: str) -> str:
    if url.startswith('socks5://'):
        return url.replace('socks5://', 'socks5h://', 1)
    if url.startswith('socks4://'):
        return url.replace('socks4://', 'socks4a://', 1)
    return url


def check_via_proxy(proxy: str, test_url: str, timeout_s: float, ip_url: str, baseline_ip: Optional[str], require_ip_change: bool, stop: threading.Event) -> bool:
    if stop.is_set():
        return False
    requests = ensure_deps()
    proxies = {"http": req_proxy_url(proxy), "https": req_proxy_url(proxy)}
    try:
        r = requests.get(test_url, proxies=proxies, timeout=timeout_s, allow_redirects=True, stream=True, headers={"User-Agent": USER_AGENT})
        if r.status_code >= 400:
            return False
        try:
            next(r.iter_content(chunk_size=1024), b"")
        finally:
            r.close()
    except Exception:
        return False
    if require_ip_change and baseline_ip:
        try:
            r = requests.get(ip_url, proxies=proxies, timeout=timeout_s, headers={"User-Agent": USER_AGENT})
            if r.status_code >= 400:
                return False
            seen_ip = extract_ip(r.text)
            if not seen_ip or seen_ip == baseline_ip:
                return False
        except Exception:
            return False
    return True


def get_baseline_ip(ip_url: str, timeout_s: float) -> Optional[str]:
    requests = ensure_deps()
    try:
        r = requests.get(ip_url, timeout=min(max(timeout_s, 1.0), 5.0), headers={"User-Agent": USER_AGENT})
        if r.status_code < 400:
            return extract_ip(r.text)
    except Exception:
        pass
    return None


class StatusPrinter:
    def __init__(self):
        self.last_len = 0
    def show(self, text: str):
        if sys.stderr.isatty():
            plain = len(ANSI_RE.sub('', text))
            pad = ' ' * max(0, self.last_len - plain)
            sys.stderr.write('\r' + text + pad)
            sys.stderr.flush()
            self.last_len = plain
        else:
            print(text, file=sys.stderr, flush=True)
    def clear(self):
        if sys.stderr.isatty() and self.last_len:
            sys.stderr.write('\r' + (' ' * self.last_len) + '\r')
            sys.stderr.flush()
            self.last_len = 0


class Shared:
    def __init__(self, need: int, output: str):
        self.need = need
        self.output = output
        self.tested = 0
        self.found = 0
        self.active = 0
        self.seen: Set[str] = set()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.file_lock = threading.Lock()
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text('', encoding='utf-8')
    def save(self, line: str):
        with self.file_lock:
            with open(self.output, 'a', encoding='utf-8', newline='\n') as f:
                f.write(line + '\n')
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass


def worker(q: 'queue.Queue[Tuple[Tuple[str,int,Optional[str],Optional[str]],Set[str],Set[str]]]', shared: Shared, test_url: str, timeout_s: float, ip_url: str, baseline_ip: Optional[str], require_ip_change: bool):
    while not shared.stop.is_set():
        try:
            item = q.get(timeout=0.25)
        except queue.Empty:
            continue
        key, hints, _sources = item
        with shared.lock:
            shared.active += 1
        try:
            result = None
            for scheme in scheme_order(hints):
                if shared.stop.is_set():
                    break
                candidate = proxy_url(key, scheme)
                if check_via_proxy(candidate, test_url, timeout_s, ip_url, baseline_ip, require_ip_change, shared.stop):
                    result = candidate
                    break
            with shared.lock:
                shared.tested += 1
                if result and result not in shared.seen and shared.found < shared.need:
                    shared.seen.add(result)
                    shared.found += 1
                    shared.save(result)
                    if shared.found >= shared.need:
                        shared.stop.set()
        finally:
            with shared.lock:
                shared.active -= 1
            q.task_done()


def prompt_need(default_need: int = DEFAULT_NEED) -> int:
    if not sys.stdin or not sys.stdin.isatty():
        return default_need
    while True:
        try:
            raw = input(f"How many working proxies do you need? [{default_need}]: ").strip()
            if not raw:
                return default_need
            value = int(raw)
            if value >= 1:
                return value
        except KeyboardInterrupt:
            print("\nCancelled by user.", file=sys.stderr)
            raise
        except Exception:
            pass
        print("Please enter a valid integer >= 1.")


def auto_per_source_limit(need: int) -> int:
    return min(DEFAULT_PER_SOURCE_LIMIT, max(3000, need * 140))


def main() -> int:
    if sys.version_info < (3, 8):
        print("ERROR: Please run with Python 3.8+.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description="Fetch and validate public proxies on the machine where this script runs.")
    parser.add_argument('--need', type=int, default=0)
    parser.add_argument('-o', '--output', default='working_proxies.txt')
    parser.add_argument('--workers', type=int, default=DEFAULT_WORKERS)
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument('--test-url', default=DEFAULT_TEST_URL)
    parser.add_argument('--ip-url', default=DEFAULT_IP_URL)
    parser.add_argument('--require-different-ip', action='store_true')
    parser.add_argument('--source-workers', type=int, default=DEFAULT_SOURCE_WORKERS)
    parser.add_argument('--per-source-limit', type=int, default=0)
    parser.add_argument('--list-sources', action='store_true')
    args = parser.parse_args()
    if args.list_sources:
        for name, urls, hint, _ in SOURCES:
            print(f"{name}\t{hint or 'mixed'}\t{urls[0]}")
        return 0

    ensure_deps()
    need = args.need if args.need > 0 else prompt_need(DEFAULT_NEED)
    workers = max(1, int(args.workers))
    timeout_s = max(0.5, float(args.timeout))
    per_source_limit = int(args.per_source_limit) if int(args.per_source_limit) > 0 else auto_per_source_limit(need)

    status = StatusPrinter()
    started = time.time()
    candidates = fetch_all_sources(per_source_limit, max(1, int(args.source_workers)), status)
    if not candidates:
        print(color('ERROR: no candidates fetched from any source.', C.R1), file=sys.stderr)
        return 1
    print(f"{color('Fetched sources', C.B1)}: {len(SOURCES)}/{len(SOURCES)} | {color('unique candidates', C.C1)}: {len(candidates):,}", file=sys.stderr)

    baseline_ip = get_baseline_ip(args.ip_url, timeout_s) if args.require_different_ip else None
    if args.require_different_ip and not baseline_ip:
        print(color('Warning: could not detect baseline IP, strict IP-change mode was disabled.', C.Y), file=sys.stderr)
        args.require_different_ip = False

    shared = Shared(need, args.output)
    q: 'queue.Queue[Tuple[Tuple[str,int,Optional[str],Optional[str]],Set[str],Set[str]]]' = queue.Queue()
    for item in candidates:
        q.put(item)

    threads = []
    for _ in range(workers):
        t = threading.Thread(target=worker, args=(q, shared, args.test_url, timeout_s, args.ip_url, baseline_ip, bool(args.require_different_ip)), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            with shared.lock:
                tested, found, active = shared.tested, shared.found, shared.active
            status.show(f"Tested {tested}/{len(candidates)} | working={color(str(found), C.G)} | need={color(str(need), C.C1)}")
            if shared.stop.is_set():
                break
            if q.empty() and active == 0:
                break
            time.sleep(0.25)
    except KeyboardInterrupt:
        shared.stop.set()
        print("\nInterrupted. Saved results remain in the output file.", file=sys.stderr)
        return 130
    finally:
        status.clear()

    elapsed = time.time() - started
    abs_out = os.path.abspath(args.output)
    print(f"Saved {color(str(shared.found), C.G)} working proxies to: {abs_out}", file=sys.stderr)
    print(f"tested={shared.tested:,} | workers={workers} | timeout={timeout_s}s | elapsed={elapsed:.2f}s", file=sys.stderr)
    if baseline_ip:
        print(f"baseline_ip={baseline_ip}", file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
