"""Merge/order invariants and the source catalog's own consistency."""

from __future__ import annotations

import pytest

from proxy_tester.constants import SCHEME_ORDER
from proxy_tester.fetching import (
    merge_unique_candidates,
    order_candidates,
    ordered_source_urls,
    source_item_limit,
)
from proxy_tester.models import ProxyCandidate, SourceSpec
from proxy_tester.sources import SOURCES


def candidate(host: str, scheme: str = "http", source: str = "s", priority: int = 10):
    return ProxyCandidate(scheme=scheme, host=host, port=80, source_name=source, source_priority=priority)


class TestSourceItemLimit:
    def test_source_cap_wins_when_no_global_limit(self):
        spec = SourceSpec("s", ("u",), "http", max_items=500)
        assert source_item_limit(spec, 0) == 500

    def test_lower_of_the_two_limits_is_used(self):
        spec = SourceSpec("s", ("u",), "http", max_items=500)
        assert source_item_limit(spec, 200) == 200
        assert source_item_limit(spec, 900) == 500

    def test_global_limit_applies_when_the_source_has_none(self):
        assert source_item_limit(SourceSpec("s", ("u",), "http"), 300) == 300

    def test_unbounded_when_neither_is_set(self):
        assert source_item_limit(SourceSpec("s", ("u",), "http"), 0) == 1_000_000


class TestOrderedSourceUrls:
    def test_healthy_mirror_is_moved_to_the_front(self):
        spec = SourceSpec("s", ("a", "b", "c"), "http")
        assert ordered_source_urls(spec, "c") == ("c", "a", "b")

    def test_original_order_is_kept_without_a_preference(self):
        spec = SourceSpec("s", ("a", "b"), "http")
        assert ordered_source_urls(spec, None) == ("a", "b")

    def test_unknown_preference_is_ignored(self):
        spec = SourceSpec("s", ("a", "b"), "http")
        assert ordered_source_urls(spec, "zzz") == ("a", "b")


class TestMergeUniqueCandidates:
    def test_duplicates_collapse_to_one(self):
        merged = merge_unique_candidates([candidate("1.1.1.1"), candidate("1.1.1.1")])
        assert len(merged) == 1

    def test_the_better_priority_wins(self):
        merged = merge_unique_candidates(
            [
                candidate("1.1.1.1", source="weak", priority=90),
                candidate("1.1.1.1", source="strong", priority=5),
            ]
        )
        assert len(merged) == 1
        assert merged[0].source_name == "strong"

    def test_priority_order_of_input_does_not_matter(self):
        merged = merge_unique_candidates(
            [
                candidate("1.1.1.1", source="strong", priority=5),
                candidate("1.1.1.1", source="weak", priority=90),
            ]
        )
        assert merged[0].source_name == "strong"

    def test_the_same_host_on_two_schemes_is_kept_separately(self):
        merged = merge_unique_candidates(
            [candidate("1.1.1.1", scheme="http"), candidate("1.1.1.1", scheme="socks5")]
        )
        assert len(merged) == 2

    def test_empty_input(self):
        assert merge_unique_candidates([]) == []


class TestOrderCandidates:
    def test_no_candidate_is_lost_or_duplicated(self):
        items = [candidate(f"1.1.1.{i}", source=f"s{i % 3}") for i in range(30)]
        ordered = order_candidates(items)
        assert len(ordered) == len(items)
        assert {c.key for c in ordered} == {c.key for c in items}

    def test_schemes_come_out_in_the_configured_order(self):
        items = [
            candidate("1.1.1.1", scheme="socks4"),
            candidate("2.2.2.2", scheme="socks5"),
            candidate("3.3.3.3", scheme="http"),
        ]
        seen = [c.scheme for c in order_candidates(items)]
        assert seen == [s for s in SCHEME_ORDER if s in seen]

    def test_sources_are_interleaved_rather_than_batched(self):
        # One 50-entry source must not monopolise the head of the queue.
        items = [candidate(f"1.1.1.{i}", source="big", priority=10) for i in range(50)]
        items += [candidate(f"2.2.2.{i}", source="small", priority=10) for i in range(5)]
        head = [c.source_name for c in order_candidates(items)[:10]]
        assert "small" in head, "a small source must appear early, not after 50 entries"

    def test_empty_input(self):
        assert order_candidates([]) == []


class TestSourceCatalog:
    def test_catalog_is_not_empty(self):
        assert len(SOURCES) > 50

    def test_names_are_unique(self):
        names = [s.name for s in SOURCES]
        assert len(names) == len(set(names)), "duplicate source name"

    @pytest.mark.parametrize("source", SOURCES, ids=lambda s: s.name)
    def test_every_source_is_well_formed(self, source):
        assert source.urls, f"{source.name} has no URL"
        assert source.scheme_hint in SCHEME_ORDER, f"{source.name}: bad scheme_hint"
        assert source.priority > 0
        assert source.max_items >= 0
        assert source.min_items >= 1
        for url in source.urls:
            assert url.startswith("https://"), f"{source.name}: {url} is not HTTPS"

    def test_all_three_protocols_are_covered(self):
        hints = {s.scheme_hint for s in SOURCES}
        assert hints == set(SCHEME_ORDER)

    def test_removed_dead_sources_have_not_crept_back(self):
        # These 404'd or were empty when the catalog was verified (2026-08-17).
        dead = ("Firmfox/proxify", "mmpx12/proxy-list", "iplocate/free-proxy-list/main/protocols/https")
        for source in SOURCES:
            for url in source.urls:
                for needle in dead:
                    assert needle not in url, f"{source.name} points at a dead list: {url}"
