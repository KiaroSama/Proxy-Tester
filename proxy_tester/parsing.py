"""Turn raw source text into validated proxy candidates."""

from __future__ import annotations

import ipaddress
import json
import re
from contextlib import suppress
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from .constants import HOSTNAME_RE, IP_BLOCK_KEYWORDS, IPV4_LIKE_RE, TOKEN_SPLIT_RE
from .models import ProxyCandidate, SourceSpec


def normalize_scheme(value: Optional[str]) -> Optional[str]:
    """Collapse source schemes onto the three proxy types we can dial."""
    if not value:
        return None
    value = value.strip().lower()
    if value == "https":
        return "http"
    if value in {"http", "socks4", "socks5"}:
        return value
    return None


def normalize_host(host: str) -> Optional[str]:
    """Canonicalize a host, rejecting dotted quads that are not valid IPv4."""
    host = host.strip().strip("[]").lower().rstrip(".")
    if not host:
        return None

    if IPV4_LIKE_RE.fullmatch(host):
        # Looks like IPv4, so it must parse as IPv4 - never fall through to the
        # hostname branch, which would happily accept "999.1.2.3".
        octets: List[str] = []
        for part in host.split("."):
            value = int(part)
            if value > 255:
                return None
            octets.append(str(value))
        return ".".join(octets)

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host if HOSTNAME_RE.fullmatch(host) else None


def is_global_host(host: str) -> bool:
    """Drop loopback, private, and reserved addresses; keep unresolved names."""
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def valid_port(value: str) -> Optional[int]:
    try:
        port = int(value)
    except Exception:
        return None
    return port if 1 <= port <= 65535 else None


def strip_token(token: str) -> str:
    """Peel quoting and punctuation noise off a token from a scraped list."""
    token = token.strip()
    token = token.strip("\"'`<>(){}")
    token = token.strip(",;")
    if not (token.startswith("[") and "]:" in token):
        token = token.strip("[]")
    return token.rstrip(".:")


def parse_host_port(raw: str) -> Optional[Tuple[str, int, Optional[str], Optional[str]]]:
    """Extract host, port, and optional credentials from one raw token."""
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


def parse_proxy_token(token: str, source: SourceSpec) -> Optional[ProxyCandidate]:
    """Parse one token into a candidate, or None when it is not a proxy."""
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


def parse_sample_candidates(text: str, source: SourceSpec, target_count: int) -> int:
    """Count distinct candidates in a short prefix, for source health checks."""
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


def extract_ip(text: str) -> Optional[str]:
    """Pull an IP out of a small JSON or plain-text response body."""

    def try_one(value: str) -> Optional[str]:
        token = value.strip().strip("\"'[](){}<>,;")
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


def looks_like_ip_block(text: str) -> bool:
    lower = (text or "").lower()
    return any(keyword in lower for keyword in IP_BLOCK_KEYWORDS)


def normalize_vies_probe_vat(vat_id: str) -> Tuple[str, str]:
    """Split a VAT ID into country and number, applying the GR/EL alias."""
    vat = re.sub(r"[^A-Za-z0-9]", "", vat_id or "").upper().strip()
    if len(vat) < 3:
        raise ValueError("VIES probe VAT ID must include a country code and number.")
    country = vat[:2]
    number = vat[2:]
    if country == "GR":
        country = "EL"
    if not country.isalpha() or not number:
        raise ValueError("VIES probe VAT ID must look like BE0545786138.")
    return country, number


def vies_vat_is_valid_response(text: str, country: str, number: str) -> bool:
    """Accept only a VIES reply that echoes back the exact VAT we asked about."""
    try:
        data = json.loads(text)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False

    valid_flag = data.get("valid")
    if isinstance(valid_flag, bool):
        is_valid = valid_flag
    else:
        legacy_flag = data.get("isValid")
        is_valid = bool(legacy_flag) if isinstance(legacy_flag, bool) else False
    if not is_valid:
        return False

    returned_country = str(data.get("countryCode") or country).strip().upper()
    returned_number = re.sub(r"[^A-Za-z0-9]", "", str(data.get("vatNumber") or number)).upper()
    expected_number = re.sub(r"[^A-Za-z0-9]", "", number).upper()
    return returned_country == country and returned_number == expected_number
