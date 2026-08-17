"""Worker pool: pull candidates off the queue, test them, save the winners."""

from __future__ import annotations

import asyncio
import ssl
import sys
import time
from collections import deque
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import Deque, Optional, Tuple

from .colors import Color
from .constants import USER_AGENT
from .models import ProxyCandidate
from .parsing import extract_ip
from .probes import (
    build_tls_context,
    candidate_hard_timeout,
    ip_check_deadline,
    probe_reachability,
    probe_vies_vat_via_proxy,
    request_via_proxy,
)
from .runtime import (
    connector_cleanup_closed_enabled,
    ensure_runtime_deps,
    maybe_raise_nofile_limit,
)
from .terminal import paint, progress_loop, status_line


class ResultWriter:
    """Append one proxy per line, flushed immediately but without fsync."""

    def __init__(self, path: str):
        self.path = path
        self.handle = None
        self.written = set()

    def __enter__(self) -> ResultWriter:
        output_path = Path(self.path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("", encoding="utf-8")
        self.written.clear()
        self.handle = output_path.open("a", encoding="utf-8", buffering=1, newline="\n")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None

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
    """Counters and stop conditions shared by every worker on the one event loop."""

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


async def fetch_direct_ip(http_session, ip_url: str) -> Optional[str]:
    """Our own public IP, needed to prove a proxy actually changes it."""
    try:
        async with http_session.get(ip_url, allow_redirects=True) as response:
            if response.status >= 400:
                return None
            body = await response.content.read(4096)
            return extract_ip(body.decode("utf-8", errors="ignore"))
    except Exception:
        return None


async def test_candidate(
    AsyncProxy,
    candidate: ProxyCandidate,
    args,
    baseline_ip: Optional[str],
    tls_context: ssl.SSLContext,
) -> bool:
    """Run the configured health probe, then optional strict IP verification."""
    rounds = max(1, int(args.stability_checks))
    for idx in range(rounds):
        round_timeout = args.timeout
        if idx > 0:
            round_timeout = max(0.35, args.timeout * args.stability_timeout_factor)

        if args.vies_check:
            passed = await probe_vies_vat_via_proxy(
                AsyncProxy=AsyncProxy,
                candidate=candidate,
                tls_context=tls_context,
                timeout_s=round_timeout,
                vat_id=args.vies_probe_vat,
            )
        else:
            passed = await probe_reachability(
                AsyncProxy=AsyncProxy,
                candidate=candidate,
                targets=args.probe_targets,
                tls_context=tls_context,
                timeout_s=round_timeout,
            )
        if not passed:
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


async def empty_queue_tail_watch(
    state: SharedState,
    queue: asyncio.Queue[ProxyCandidate],
    tail_timeout_s: float,
) -> None:
    """Stop the run once only the slow final stragglers are still in flight."""
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


async def worker_loop(
    state: SharedState,
    queue: asyncio.Queue[ProxyCandidate],
    AsyncProxy,
    args,
    baseline_ip: Optional[str],
    tls_context: ssl.SSLContext,
    writer: ResultWriter,
    hard_timeout_s: float,
) -> None:
    """Take one candidate at a time until the queue drains or we have enough."""
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
        finally:
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
            if not writer.write_line(proxy_url):
                continue
            state.seen_working.add(proxy_url)
            state.found += 1
            if state.found >= state.need:
                state.stop_event.set()
                return


async def run_checks(candidates: Sequence[ProxyCandidate], args) -> Tuple[int, int, float, Optional[str]]:
    """Drive the whole worker pool and stop as soon as we have enough proxies."""
    aiohttp, python_socks_asyncio = ensure_runtime_deps()
    AsyncProxy = python_socks_asyncio.Proxy

    maybe_raise_nofile_limit(args.workers)

    timeout = aiohttp.ClientTimeout(total=max(0.5, args.timeout))
    connector = aiohttp.TCPConnector(
        limit=0,
        ttl_dns_cache=300,
        enable_cleanup_closed=connector_cleanup_closed_enabled(),
    )
    state = SharedState(need=args.need)
    tls_context = build_tls_context(args.verify_tls)

    queue: asyncio.Queue[ProxyCandidate] = asyncio.Queue()
    for candidate in candidates:
        queue.put_nowait(candidate)

    with ResultWriter(args.output) as writer:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            trust_env=False,
        ) as http_session:
            baseline_ip = None
            if args.require_different_ip:
                baseline_ip = await fetch_direct_ip(http_session, args.ip_url)
                if not baseline_ip:
                    print(
                        paint(
                            "Warning: could not detect baseline IP, strict IP-change mode was disabled.",
                            Color.WARNING,
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
                    {gather_future, stop_waiter}, return_when=asyncio.FIRST_COMPLETED
                )
                if stop_waiter in done and not gather_future.done():
                    # Two-phase shutdown: a short grace period, then a hard cancel.
                    grace = min(0.2, max(0.05, args.tail_drain_timeout * 0.25))
                    with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                        await asyncio.wait_for(gather_future, timeout=grace)
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
                print(
                    "\r" + status_line(state, len(candidates)) + " " * 10,
                    file=sys.stderr,
                    flush=True,
                )

    elapsed = time.time() - state.started_at
    return state.tested, state.found, elapsed, baseline_ip
