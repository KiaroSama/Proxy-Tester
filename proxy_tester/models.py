"""Immutable value objects passed between fetching, probing, and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import quote

CandidateKey = Tuple[str, str, int, Optional[str], Optional[str]]


def format_host(host: str) -> str:
    """Bracket IPv6 literals, but only when serializing a host:port pair."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


@dataclass(frozen=True)
class SourceSpec:
    """One proxy source plus how much we trust and prefer it."""

    name: str
    urls: Tuple[str, ...]
    scheme_hint: str
    priority: int = 50
    max_items: int = 0
    min_items: int = 1


@dataclass(frozen=True)
class ProxyCandidate:
    """One proxy candidate plus lightweight provenance metadata."""

    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    source_name: str = ""
    source_priority: int = 100

    @property
    def key(self) -> CandidateKey:
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
    """A probe URL parsed once, so workers never re-parse it per proxy."""

    scheme: str
    host: str
    port: int
    path_qs: str
    expected_status: Optional[int] = None


@dataclass
class SourceResult:
    """Short fetch summary for one source, used by the run report."""

    source: SourceSpec
    count: int
    error: Optional[str] = None
