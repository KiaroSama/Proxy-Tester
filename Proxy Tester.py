#!/usr/bin/env python3
"""
proxy_fetcher_speedx_vies_tested_prompt_nolimit.py

Downloads the latest SOCKS5, SOCKS4, and HTTP proxy lists from TheSpeedX,
tests each proxy against the VIES website (EU Commission) with a per-test
timeout (default: 3 seconds), and saves ONLY the working ones into a single
output file, one proxy per line, formatted like:

socks5://1.2.3.4:1080
socks4://1.2.3.4:1080
http://1.2.3.4:8080

This version PROMPTS you at runtime for the number of concurrent tests (workers).
It does NOT enforce a hard cap in the script.

Notes:
- Public proxies are untrusted. Do not send sensitive data through them.
- Many public proxies are dead/slow/unreliable.
- Very high concurrency can cause local resource limits or remote throttling.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# Primary: PROXY-List, Fallback: SOCKS-List (the repo README links to SOCKS-List raw URLs)
SOURCES: Sequence[Tuple[str, Sequence[str]]] = (
    ("socks5", (
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    )),
    ("socks4", (
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    )),
    ("http", (
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    )),
)

# Simple IP:PORT detector (input lists are typically one per line)
IP_PORT_RE = re.compile(r"^\s*([0-9a-fA-F\.\:]+)\s*:\s*([0-9]{1,5})\s*$")
IPV4_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _python_version_ok() -> bool:
    return sys.version_info >= (3, 8)


def _try_install(package: str) -> bool:
    """Try to install a Python package via pip; returns True if it seems successful."""
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--user", package],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def _ensure_requests_and_socks():
    """
    Ensure 'requests' is available. For SOCKS proxies, ensure PySocks is available.
    Installs missing deps automatically when possible.
    """
    try:
        import requests  # type: ignore
    except Exception:
        if not _try_install("requests"):
            raise RuntimeError("Missing dependency: requests (and auto-install failed).")
        import requests  # type: ignore

    # PySocks module name is "socks"
    try:
        import socks  # type: ignore  # noqa: F401
    except Exception:
        _try_install("pysocks")
        try:
            import socks  # type: ignore  # noqa: F401
        except Exception:
            # If it still fails, SOCKS tests may fail. We'll handle that at runtime.
            pass

    return requests


def _download_text(urls: Sequence[str], timeout_s: int = 25, retries: int = 3) -> str:
    """Download text content from the first working URL in 'urls'."""
    requests = _ensure_requests_and_socks()
    last_err: Optional[Exception] = None

    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                resp = requests.get(url, timeout=timeout_s, headers={"User-Agent": "proxy-fetcher/1.4"})
                resp.raise_for_status()
                resp.encoding = resp.encoding or "utf-8"
                return resp.text
            except Exception as e:
                last_err = e
                time.sleep(min(2 ** (attempt - 1), 4))

    raise RuntimeError(f"All downloads failed. Last error: {last_err}")


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def _is_valid_port(port: str) -> bool:
    try:
        p = int(port)
        return 1 <= p <= 65535
    except Exception:
        return False


def _parse_proxy_lines(text: str) -> List[Tuple[str, str]]:
    """Return a list of (ip, port) tuples filtered to valid IPs and ports."""
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        m = IP_PORT_RE.match(line)
        if not m:
            continue
        ip, port = m.group(1), m.group(2)
        if _is_valid_ip(ip) and _is_valid_port(port):
            out.append((ip, port))
    return out


def _bracket_if_ipv6(ip: str) -> str:
    try:
        if ipaddress.ip_address(ip).version == 6:
            return f"[{ip}]"
    except Exception:
        pass
    return ip


def _format_proxies(scheme: str, items: Iterable[Tuple[str, str]]) -> List[str]:
    out: List[str] = []
    for ip, port in items:
        host = _bracket_if_ipv6(ip)
        out.append(f"{scheme}://{host}:{port}")
    return out


def _scheme_to_requests_proxy(scheme: str, proxy_url: str) -> str:
    """Convert scheme to a requests-compatible proxy URL."""
    if scheme == "socks5":
        return proxy_url.replace("socks5://", "socks5h://", 1)
    if scheme == "socks4":
        return proxy_url.replace("socks4://", "socks4a://", 1)
    return proxy_url


def fetch_all(order: Sequence[str]) -> List[Tuple[str, int, str]]:
    """
    Fetch proxies in the given order and return a combined, de-duplicated list.
    Each entry is (scheme, index_within_scheme, formatted_proxy_url).
    """
    scheme_to_urls = {scheme: urls for scheme, urls in SOURCES}

    seen = set()
    combined: List[Tuple[str, int, str]] = []

    for scheme in order:
        if scheme not in scheme_to_urls:
            raise ValueError(f"Unknown scheme '{scheme}'. Valid: socks5, socks4, http")

        text = _download_text(scheme_to_urls[scheme])
        pairs = _parse_proxy_lines(text)
        formatted = _format_proxies(scheme, pairs)

        idx = 0
        for item in formatted:
            if item in seen:
                continue
            seen.add(item)
            combined.append((scheme, idx, item))
            idx += 1

    return combined


def _extract_ip_from_json_like(text: str) -> Optional[str]:
    """Best-effort: extract an IPv4 from JSON-like responses (ipify/httpbin/etc.)."""
    try:
        data = json.loads(text)
        for key in ("ip", "origin"):
            val = data.get(key)
            if isinstance(val, str):
                parts = [x.strip() for x in val.split(",") if x.strip()]
                for p in parts:
                    if IPV4_EXTRACT_RE.fullmatch(p):
                        return p
    except Exception:
        pass

    m = IPV4_EXTRACT_RE.search(text)
    return m.group(0) if m else None


def _test_vies_page(
    requests,
    proxies: Dict[str, str],
    test_url: str,
    timeout_s: float,
) -> bool:
    """
    Test proxy by requesting the VIES page.
    Uses stream=True and reads a small chunk to confirm data flow.
    """
    try:
        r = requests.get(
            test_url,
            proxies=proxies,
            timeout=timeout_s,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": "proxy-check/1.4"},
        )
        if r.status_code >= 400:
            return False

        try:
            _ = next(r.iter_content(chunk_size=1024), b"")
        finally:
            r.close()

        return True
    except Exception:
        return False


def _test_one_proxy(
    scheme: str,
    proxy_url: str,
    test_url: str,
    timeout_s: float,
    require_different_ip: bool,
    my_ip: Optional[str],
    ip_url: str,
) -> bool:
    """
    Return True if:
    1) proxy can reach the VIES test_url within timeout, and
    2) (optional) the proxy changes the observed public IP.
    """
    requests = _ensure_requests_and_socks()

    req_proxy_url = _scheme_to_requests_proxy(scheme, proxy_url)
    proxies: Dict[str, str] = {"http": req_proxy_url, "https": req_proxy_url}

    if not _test_vies_page(requests, proxies, test_url, timeout_s):
        return False

    if require_different_ip and my_ip:
        try:
            r = requests.get(
                ip_url,
                proxies=proxies,
                timeout=timeout_s,
                headers={"User-Agent": "proxy-check/1.4"},
            )
            if r.status_code >= 400:
                return False
            observed = _extract_ip_from_json_like(r.text)
            if not observed or observed == my_ip:
                return False
        except Exception:
            return False

    return True


def _prompt_workers(default_workers: int = 50) -> int:
    """
    Ask the user how many concurrent tests to run.
    If stdin is not interactive, return default_workers.
    """
    if not sys.stdin or not sys.stdin.isatty():
        return max(1, int(default_workers))

    while True:
        try:
            raw = input(f"How many concurrent tests? [{default_workers}]: ").strip()
            if not raw:
                return max(1, int(default_workers))
            n = int(raw)
            if n < 1:
                print("Please enter a number >= 1.")
                continue
            if n > 200:
                print("Warning: very high concurrency may trigger throttling or local resource limits.", file=sys.stderr)
            return n
        except KeyboardInterrupt:
            print("\nCancelled by user.", file=sys.stderr)
            raise
        except Exception:
            print("Please enter a valid integer.")


def main() -> int:
    if not _python_version_ok():
        print("ERROR: Please run with Python 3.8+.", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(
        description="Download SOCKS5/SOCKS4/HTTP proxies from TheSpeedX, test them on VIES, and save only the working ones."
    )
    parser.add_argument(
        "-o", "--output",
        default="proxies_working.txt",
        help="Output filename (default: proxies_working.txt)"
    )
    parser.add_argument(
        "--order",
        default="socks5,socks4,http",
        help="Comma-separated order (default: socks5,socks4,http)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Timeout (seconds) per proxy test (default: 3.0)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Number of concurrent tests. If omitted/0, you will be prompted at runtime."
    )
    parser.add_argument(
        "--test-url",
        default="https://ec.europa.eu/taxation_customs/vies/",
        help="URL used for testing reachability (default: https://ec.europa.eu/taxation_customs/vies/)"
    )
    parser.add_argument(
        "--ip-url",
        default="https://api.ipify.org?format=json",
        help="URL used to detect public IP (default: https://api.ipify.org?format=json)"
    )
    parser.add_argument(
        "--require-different-ip",
        action="store_true",
        help="Strict mode: only keep proxies that change your observed public IP."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional limit on number of proxies to test (0 = no limit)."
    )
    args = parser.parse_args()

    order = [x.strip().lower() for x in args.order.split(",") if x.strip()]
    if not order:
        print("ERROR: --order is empty.", file=sys.stderr)
        return 2

    require_different_ip = bool(args.require_different_ip)

    # Determine workers (no hard cap enforced by the script)
    workers = int(args.workers) if args.workers and args.workers > 0 else _prompt_workers(default_workers=50)

    # Guard: ThreadPoolExecutor requires max_workers >= 1
    workers = max(1, workers)

    try:
        all_proxies = fetch_all(order)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.limit and args.limit > 0:
        all_proxies = all_proxies[: args.limit]

    # Baseline public IP (used only in strict mode)
    my_ip: Optional[str] = None
    if require_different_ip:
        # Best-effort baseline; if it fails, strict mode will likely be too strict.
        try:
            requests = _ensure_requests_and_socks()
            r = requests.get(args.ip_url, timeout=min(max(args.timeout, 1.0), 5.0), headers={"User-Agent": "proxy-fetcher/1.4"})
            if r.status_code < 400:
                my_ip = _extract_ip_from_json_like(r.text)
        except Exception:
            my_ip = None

    total = len(all_proxies)
    tested = 0
    ok_count = 0
    ok_results: List[Tuple[str, int, str]] = []

    def _task(item: Tuple[str, int, str]) -> Tuple[Tuple[str, int, str], bool]:
        scheme, idx, proxy_url = item
        ok = _test_one_proxy(
            scheme=scheme,
            proxy_url=proxy_url,
            test_url=args.test_url,
            timeout_s=args.timeout,
            require_different_ip=require_different_ip,
            my_ip=my_ip,
            ip_url=args.ip_url,
        )
        return item, ok

    def _print_progress():
        print(f"Tested {tested}/{total} | Working: {ok_count}", file=sys.stderr)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_task, item) for item in all_proxies]
        for fut in cf.as_completed(futures):
            item, ok = fut.result()
            tested += 1
            if ok:
                ok_results.append(item)
                ok_count += 1
            if tested % 50 == 0 or tested == total:
                _print_progress()

    scheme_rank = {scheme: i for i, scheme in enumerate(order)}
    ok_results.sort(key=lambda x: (scheme_rank.get(x[0], 999), x[1]))

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for _, __, proxy_url in ok_results:
            f.write(proxy_url + "\n")

    abs_out = os.path.abspath(args.output)
    print(f"Saved {len(ok_results):,}/{total:,} working proxies to: {abs_out}")
    print(f"test_url={args.test_url} | timeout={args.timeout}s | workers={workers} | strict_ip_change={require_different_ip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
