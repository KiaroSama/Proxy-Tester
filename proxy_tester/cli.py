"""Command line interface and program entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Iterable

from . import __version__
from .constants import (
    DEFAULT_IP_URL,
    DEFAULT_NEED,
    DEFAULT_OUTPUT,
    DEFAULT_PER_SOURCE_LIMIT,
    DEFAULT_PROBE_URLS,
    DEFAULT_SOURCE_BATCH_SIZE,
    DEFAULT_SOURCE_HEALTH_BYTES,
    DEFAULT_SOURCE_HEALTH_TIMEOUT,
    DEFAULT_SOURCE_TIMEOUT,
    DEFAULT_SOURCE_WORKERS,
    DEFAULT_STABILITY_CHECKS,
    DEFAULT_STABILITY_TIMEOUT_FACTOR,
    DEFAULT_TAIL_DRAIN_TIMEOUT,
    DEFAULT_TAIL_EMPTY_TIMEOUT,
    DEFAULT_TIMEOUT,
    DEFAULT_VIES_PROBE_VAT_ID,
    DEFAULT_WORKERS,
)
from .fetching import fetch_all_sources
from .models import SourceResult
from .parsing import normalize_vies_probe_vat
from .probes import build_probe_targets
from .runner import run_checks
from .runtime import install_asyncio_exception_filter, python_version_ok
from .sources import SOURCES
from .terminal import Ansi, paint


def prompt_for_need(default_need: int = DEFAULT_NEED) -> int:
    """Ask interactively, but only when stdin is a real terminal."""
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
    """Parse enough per source to satisfy the request without over-downloading."""
    return min(6000, max(1200, need * 45))


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
        preview = ", ".join(item.source.name for item in failed_rows[:10])
        more = f", +{len(failed_rows) - 10} more" if len(failed_rows) > 10 else ""
        print(f"failed/skipped ({len(failed_rows)}): {preview}{more}", file=sys.stderr)


def list_sources() -> None:
    for item in sorted(SOURCES, key=lambda source: (source.priority, source.name)):
        print(f"{item.priority}\t{item.name}\t{item.scheme_hint}\t{item.urls[0]}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="proxy-tester",
        description=(
            "Fetch public proxies from curated sources, test them concurrently, "
            "and save the working ones to a single file."
        ),
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--need", type=int, default=0, help="How many working proxies to save.")
    ap.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output file for working proxies (default: {DEFAULT_OUTPUT}).",
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
        help=f"Successful probe rounds a proxy must pass (default: {DEFAULT_STABILITY_CHECKS}).",
    )
    ap.add_argument(
        "--stability-timeout-factor",
        type=float,
        default=DEFAULT_STABILITY_TIMEOUT_FACTOR,
        help=(
            "Timeout multiplier for stability rounds after the first success "
            f"(default: {DEFAULT_STABILITY_TIMEOUT_FACTOR})."
        ),
    )
    ap.add_argument(
        "--tail-drain-timeout",
        type=float,
        default=DEFAULT_TAIL_DRAIN_TIMEOUT,
        help=f"Seconds to wait for worker cancellation after stop (default: {DEFAULT_TAIL_DRAIN_TIMEOUT}).",
    )
    ap.add_argument(
        "--tail-empty-timeout",
        type=float,
        default=DEFAULT_TAIL_EMPTY_TIMEOUT,
        help=(
            "Seconds to keep the last checks running after the queue empties. "
            f"0 waits for every candidate (default: {DEFAULT_TAIL_EMPTY_TIMEOUT})."
        ),
    )

    probe = ap.add_argument_group("health probe")
    probe.add_argument(
        "--test-url",
        action="append",
        dest="test_urls",
        default=None,
        help=(
            "Probe URL, repeatable. The first endpoint to answer marks the proxy alive. "
            f"Defaults to: {', '.join(DEFAULT_PROBE_URLS)}"
        ),
    )
    probe.add_argument(
        "--vies-check",
        action="store_true",
        help=(
            "Validate a known-good VAT ID through the EU VIES API instead of the fast "
            "reachability probe. Far slower and aggressively rate limited: use it only "
            "when a proxy must be proven to work against VIES specifically."
        ),
    )
    probe.add_argument(
        "--vies-probe-vat",
        default=DEFAULT_VIES_PROBE_VAT_ID,
        help=f"VAT ID used by --vies-check (default: {DEFAULT_VIES_PROBE_VAT_ID}).",
    )
    probe.add_argument(
        "--ip-url",
        default=DEFAULT_IP_URL,
        help="URL used to detect the public IP in strict mode.",
    )
    probe.add_argument(
        "--require-different-ip",
        action="store_true",
        help="Keep only proxies that demonstrably change the observed public IP.",
    )
    probe.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates during checks. Off by default for speed.",
    )

    src = ap.add_argument_group("sources")
    src.add_argument(
        "--source-timeout",
        type=float,
        default=DEFAULT_SOURCE_TIMEOUT,
        help=f"Timeout for source downloads (default: {DEFAULT_SOURCE_TIMEOUT}).",
    )
    src.add_argument(
        "--source-health-timeout",
        type=float,
        default=DEFAULT_SOURCE_HEALTH_TIMEOUT,
        help=f"Timeout for source health pre-checks (default: {DEFAULT_SOURCE_HEALTH_TIMEOUT}).",
    )
    src.add_argument(
        "--source-health-bytes",
        type=int,
        default=DEFAULT_SOURCE_HEALTH_BYTES,
        help=f"Bytes sampled when validating a source (default: {DEFAULT_SOURCE_HEALTH_BYTES}).",
    )
    src.add_argument(
        "--source-workers",
        type=int,
        default=DEFAULT_SOURCE_WORKERS,
        help=f"Concurrent source downloads per batch (default: {DEFAULT_SOURCE_WORKERS}).",
    )
    src.add_argument(
        "--source-batch-size",
        type=int,
        default=DEFAULT_SOURCE_BATCH_SIZE,
        help=(
            "Sources per batch before re-checking the candidate count "
            f"(default: {DEFAULT_SOURCE_BATCH_SIZE})."
        ),
    )
    src.add_argument(
        "--per-source-limit",
        type=int,
        default=DEFAULT_PER_SOURCE_LIMIT,
        help="Max parsed proxies per source. 0 = automatic.",
    )
    src.add_argument(
        "--skip-source-health-check",
        action="store_true",
        help="Skip the cheap source health pre-check.",
    )
    src.add_argument(
        "--list-sources",
        action="store_true",
        help="Print the built-in source catalog and exit.",
    )
    return ap


async def async_main(args) -> int:
    install_asyncio_exception_filter()

    candidates, source_results = await fetch_all_sources(args)
    if not candidates:
        print(paint("ERROR: no candidates fetched from any source.", Ansi.RED), file=sys.stderr)
        return 1

    print_source_summary(source_results, len(candidates))
    if args.vies_check:
        probe_description = f"VIES VAT {paint(args.vies_probe_vat, Ansi.YELLOW)} must return valid=true"
    else:
        probe_description = f"reachability via {paint(str(len(args.probe_targets)), Ansi.YELLOW)} endpoint(s)"
    print(f"Proxy health probe: {probe_description}.", file=sys.stderr)

    tested, found, elapsed, baseline_ip = await run_checks(candidates, args)
    abs_out = os.path.abspath(args.output)

    print(f"Saved {paint(str(found), Ansi.GREEN)} working proxies to: {abs_out}", file=sys.stderr)
    print(
        f"tested={tested:,} | workers={args.workers} | timeout={args.timeout}s | "
        f"stability_checks={args.stability_checks} | elapsed={elapsed:.2f}s",
        file=sys.stderr,
    )
    if baseline_ip:
        print(f"baseline_ip={baseline_ip}", file=sys.stderr)

    if found < args.need:
        if tested >= len(candidates):
            message = (
                f"Warning: only {found} working proxies were found after checking "
                f"all {len(candidates):,} candidates."
            )
        else:
            message = (
                f"Warning: stopped after {tested:,}/{len(candidates):,} candidates. "
                "Use --tail-empty-timeout 0 for a complete check."
            )
        print(paint(message, Ansi.YELLOW), file=sys.stderr)
    return 0


def _normalize_args(args) -> None:
    """Clamp every numeric option into a range the run can actually honour."""
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


def main(argv=None) -> int:
    if not python_version_ok():
        print("ERROR: Please run with Python 3.9+.", file=sys.stderr)
        return 2

    args = build_parser().parse_args(argv)

    if args.list_sources:
        list_sources()
        return 0

    if args.need <= 0:
        args.need = prompt_for_need(DEFAULT_NEED)

    _normalize_args(args)

    try:
        country, number = normalize_vies_probe_vat(args.vies_probe_vat)
        args.vies_probe_vat = country + number
        args.probe_targets = build_probe_targets(args.test_urls or list(DEFAULT_PROBE_URLS))
        args.ip_target = build_probe_targets([args.ip_url])[0]
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted. Saved results remain in the output file.", file=sys.stderr)
        return 130
