"""Download proxy lists from the curated sources and merge them into a queue."""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from typing import Deque, Dict, List, Optional, Tuple

from .constants import (
    DEFAULT_CANDIDATE_MULTIPLIER,
    SCHEME_ORDER,
    TOKEN_SPLIT_RE,
    USER_AGENT,
)
from .models import CandidateKey, ProxyCandidate, SourceResult, SourceSpec
from .parsing import parse_proxy_token, parse_sample_candidates
from .runtime import connector_cleanup_closed_enabled, ensure_runtime_deps
from .sources import SOURCES


def source_item_limit(source: SourceSpec, per_source_limit: int) -> int:
    """Effective parse cap for one source, combining its cap and the global one."""
    limit = source.max_items or per_source_limit
    if source.max_items and per_source_limit > 0:
        limit = min(source.max_items, per_source_limit)
    elif per_source_limit > 0:
        limit = per_source_limit
    if limit <= 0:
        limit = 1_000_000
    return limit


async def read_text_tokens(response, source: SourceSpec, per_source_limit: int) -> List[ProxyCandidate]:
    """Stream and parse a list without holding the whole response in memory."""
    limit = source_item_limit(source, per_source_limit)

    found: List[ProxyCandidate] = []
    seen = set()
    buffer = ""

    async for chunk in response.content.iter_chunked(65536):
        buffer += chunk.decode("utf-8", errors="ignore")
        parts = TOKEN_SPLIT_RE.split(buffer)
        # Keep the trailing fragment: it may be a token split across chunks.
        buffer = parts.pop() if parts else ""
        for token in parts:
            candidate = parse_proxy_token(token, source)
            if candidate is None or candidate.key in seen:
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


async def probe_source_url(
    session,
    source: SourceSpec,
    url: str,
    timeout_s: float,
    sample_bytes: int,
) -> Tuple[bool, Optional[str]]:
    """Range-request a small prefix to decide whether a source is worth fetching."""
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


def ordered_source_urls(source: SourceSpec, preferred_url: Optional[str] = None) -> Tuple[str, ...]:
    """Try the mirror that passed the health check first."""
    if not preferred_url or preferred_url not in source.urls:
        return source.urls
    return (preferred_url,) + tuple(url for url in source.urls if url != preferred_url)


async def fetch_one_source(
    session,
    source: SourceSpec,
    per_source_limit: int,
    preferred_url: Optional[str] = None,
) -> Tuple[SourceResult, List[ProxyCandidate]]:
    """Fetch one source, walking its mirrors until one yields parsable data."""
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
                return (
                    SourceResult(source=source, count=len(items), url_used=url, error=None),
                    items,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_error = str(exc)
    return (
        SourceResult(source=source, count=0, url_used=None, error=last_error or "download failed"),
        [],
    )


def merge_unique_candidates(candidates: Iterable[ProxyCandidate]) -> List[ProxyCandidate]:
    """De-duplicate, keeping the entry from the highest-priority source."""
    merged: Dict[CandidateKey, ProxyCandidate] = {}
    for candidate in candidates:
        existing = merged.get(candidate.key)
        if existing is None or candidate.source_priority < existing.source_priority:
            merged[candidate.key] = candidate
    return list(merged.values())


def order_candidates(candidates: Sequence[ProxyCandidate]) -> List[ProxyCandidate]:
    """Round-robin across sources so one weak list cannot dominate the queue."""
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


async def _health_check_sources(
    session,
    sources: Sequence[SourceSpec],
    args,
    results: List[SourceResult],
) -> Tuple[List[SourceSpec], Dict[str, str]]:
    """Drop sources that fail a cheap prefix check, and remember the live mirror."""
    semaphore = asyncio.Semaphore(max(1, args.source_workers))

    async def bounded_health(source: SourceSpec):
        async with semaphore:
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

    rows = await asyncio.gather(*(bounded_health(source) for source in sources), return_exceptions=True)

    healthy: List[SourceSpec] = []
    preferred_urls: Dict[str, str] = {}
    for source, row in zip(sources, rows):
        if isinstance(row, BaseException):
            results.append(SourceResult(source=source, count=0, error=f"health: {row}"))
            continue
        _, preferred_url, error = row
        if not preferred_url:
            results.append(SourceResult(source=source, count=0, error=f"health: {error}"))
            continue
        preferred_urls[source.name] = preferred_url
        healthy.append(source)
    return healthy, preferred_urls


async def fetch_all_sources(args) -> Tuple[List[ProxyCandidate], List[SourceResult]]:
    """Fetch sources in priority batches, stopping once we have enough candidates."""
    aiohttp, _ = ensure_runtime_deps()
    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=max(5.0, args.source_timeout))
    connector = aiohttp.TCPConnector(
        limit=0,
        ttl_dns_cache=300,
        enable_cleanup_closed=connector_cleanup_closed_enabled(),
    )

    candidate_goal = max(1000, args.need * DEFAULT_CANDIDATE_MULTIPLIER)
    per_source_limit = args.per_source_limit
    ordered_sources = sorted(SOURCES, key=lambda item: (item.priority, item.name))

    merged: Dict[CandidateKey, ProxyCandidate] = {}
    results: List[SourceResult] = []
    preferred_urls: Dict[str, str] = {}

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=headers, trust_env=False
    ) as session:
        if not args.skip_source_health_check:
            ordered_sources, preferred_urls = await _health_check_sources(
                session, ordered_sources, args, results
            )

        batch_size = max(1, args.source_batch_size)
        for start in range(0, len(ordered_sources), batch_size):
            batch = ordered_sources[start : start + batch_size]
            semaphore = asyncio.Semaphore(max(1, min(args.source_workers, len(batch))))

            async def bounded_fetch(source: SourceSpec, sem=semaphore):
                async with sem:
                    return await fetch_one_source(
                        session=session,
                        source=source,
                        per_source_limit=per_source_limit,
                        preferred_url=preferred_urls.get(source.name),
                    )

            gathered = await asyncio.gather(
                *(bounded_fetch(source) for source in batch), return_exceptions=True
            )

            for source, item in zip(batch, gathered):
                if isinstance(item, BaseException):
                    results.append(SourceResult(source=source, count=0, error=str(item)))
                    continue
                result, items = item
                results.append(result)
                for candidate in items:
                    existing = merged.get(candidate.key)
                    if existing is None or candidate.source_priority < existing.source_priority:
                        merged[candidate.key] = candidate

            if len(merged) >= candidate_goal:
                break

    return order_candidates(list(merged.values())), results
