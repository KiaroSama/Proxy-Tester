"""Tunable defaults, regexes, and probe endpoints shared across the package."""

from __future__ import annotations

import re
from typing import Tuple

USER_AGENT = "proxy-tester/17.0"

# How many working proxies to collect when the user does not say.
DEFAULT_NEED = 50

# Per-proxy budget. Reachability probes answer in well under a second when the
# proxy is alive, so a long timeout only pays for dead hosts.
DEFAULT_TIMEOUT = 6.0

# Source download budgets.
DEFAULT_SOURCE_TIMEOUT = 15.0
DEFAULT_SOURCE_HEALTH_TIMEOUT = 4.5
DEFAULT_SOURCE_HEALTH_BYTES = 16384
DEFAULT_SOURCE_WORKERS = 20
DEFAULT_PER_SOURCE_LIMIT = 0
DEFAULT_SOURCE_BATCH_SIZE = 10

# Fetch this many candidates per requested proxy before we stop pulling sources.
DEFAULT_CANDIDATE_MULTIPLIER = 60

RECENT_RATE_WINDOW = 4.0
PROBE_DEADLINE_GRACE = 0.15
STRICT_IP_TIMEOUT_CAP = 1.5

DEFAULT_STABILITY_CHECKS = 1
DEFAULT_STABILITY_TIMEOUT_FACTOR = 0.8
DEFAULT_TAIL_DRAIN_TIMEOUT = 0.9
DEFAULT_TAIL_EMPTY_TIMEOUT = 0.0
WRITER_CLOSE_TIMEOUT = 0.25

# Default worker pool. The old build used 3000 workers aimed at a single
# rate-limited government API, which throttled itself; the fast probe endpoints
# below are CDN-backed and absorb this comfortably.
DEFAULT_WORKERS = 1000

DEFAULT_OUTPUT = "output/working_proxies.txt"

DEFAULT_IP_URL = "https://api.ipify.org?format=json"

# Default health probe: tiny endpoints, one round trip, no TLS, nothing to parse.
# probe_reachability takes the first one that answers, so order and provider
# diversity both matter:
#   - Google 403s known proxy IPs, so a Google-only list rejects live proxies.
#   - example.com blocks nothing, making it the honest last resort.
# Measured 2026-08-17: proxies that pass cloudflare/example.com but 403 on
# gstatic do forward correctly (verified against the real example.com body and
# a bogus-Host control), so a gstatic 403 alone must never condemn a proxy.
DEFAULT_PROBE_URLS: Tuple[str, ...] = (
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://example.com/",
)

# Optional deep check: validate a known-good VAT ID through the EU VIES API.
# Far slower and aggressively rate limited, so it is opt-in via --vies-check.
VIES_API_BASE_URL = "https://ec.europa.eu/taxation_customs/vies/rest-api"
VIES_CHECK_VAT_URL = VIES_API_BASE_URL + "/check-vat-number"
DEFAULT_VIES_PROBE_VAT_ID = "BE0545786138"
VIES_API_ACCEPT = "application/json, text/plain;q=0.9, */*;q=0.8"
VIES_RESPONSE_BODY_LIMIT = 65536

SCHEME_ORDER: Tuple[str, ...] = ("http", "socks5", "socks4")

TOKEN_SPLIT_RE = re.compile(r"[\s,;]+")
IPV4_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")

# Phrases that mean the upstream service rejected us rather than the proxy.
IP_BLOCK_KEYWORDS = (
    "your ip address is currently blocked",
    "your request for vat validation has not been processed",
    "ip address is currently blocked",
    "please contact taxud-viesweb@ec.europa.eu",
    "taxud-viesweb@ec.europa.eu",
    "ip blocked",
    "temporarily blocked",
    "rate limit",
    "rate-limited",
    "too many requests",
    "access denied",
    "blocked",
)
