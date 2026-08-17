"""Parsing is the layer that decides what counts as a proxy, so it carries the
bulk of the coverage: everything downstream trusts these results."""

from __future__ import annotations

import pytest

from proxy_tester.models import ProxyCandidate, SourceSpec, format_host
from proxy_tester.parsing import (
    extract_ip,
    is_global_host,
    looks_like_ip_block,
    normalize_host,
    normalize_scheme,
    normalize_vies_probe_vat,
    parse_host_port,
    parse_proxy_token,
    parse_sample_candidates,
    strip_token,
    valid_port,
    vies_vat_is_valid_response,
)

HTTP_SOURCE = SourceSpec(name="t_http", urls=("http://x/",), scheme_hint="http", priority=1)
SOCKS5_SOURCE = SourceSpec(name="t_s5", urls=("http://x/",), scheme_hint="socks5", priority=2)


class TestNormalizeScheme:
    def test_https_collapses_to_http(self):
        assert normalize_scheme("https") == "http"

    @pytest.mark.parametrize("value", ["http", "socks4", "socks5"])
    def test_supported_schemes_pass_through(self, value):
        assert normalize_scheme(value) == value

    def test_case_and_padding_are_ignored(self):
        assert normalize_scheme("  SOCKS5 ") == "socks5"

    @pytest.mark.parametrize("value", [None, "", "ftp", "socks6"])
    def test_unsupported_returns_none(self, value):
        assert normalize_scheme(value) is None


class TestNormalizeHost:
    def test_plain_ipv4(self):
        assert normalize_host("8.8.8.8") == "8.8.8.8"

    def test_zero_padded_octets_are_canonicalized(self):
        # gfpcom publishes addresses like 001.224.3.122.
        assert normalize_host("001.224.003.122") == "1.224.3.122"

    def test_octet_above_255_is_rejected(self):
        # Regression: this must not fall through to the hostname branch.
        assert normalize_host("999.1.2.3") is None

    def test_trailing_dot_and_case_are_stripped(self):
        assert normalize_host("Example.COM.") == "example.com"

    def test_ipv6_is_compressed(self):
        assert normalize_host("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"

    def test_hostname_is_kept(self):
        assert normalize_host("proxy.example.org") == "proxy.example.org"

    @pytest.mark.parametrize("value", ["", "   ", "-bad.example.com", "not_valid!"])
    def test_junk_is_rejected(self, value):
        assert normalize_host(value) is None


class TestIsGlobalHost:
    @pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1"])
    def test_non_routable_addresses_are_excluded(self, value):
        assert is_global_host(value) is False

    def test_public_address_is_included(self):
        assert is_global_host("8.8.8.8") is True

    def test_unresolved_hostname_is_given_the_benefit_of_the_doubt(self):
        assert is_global_host("proxy.example.org") is True


class TestValidPort:
    @pytest.mark.parametrize("value,expected", [("1", 1), ("8080", 8080), ("65535", 65535)])
    def test_valid_range(self, value, expected):
        assert valid_port(value) == expected

    @pytest.mark.parametrize("value", ["0", "65536", "-1", "", "abc", "80.5"])
    def test_invalid_values(self, value):
        assert valid_port(value) is None


class TestStripToken:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ('"1.2.3.4:80"', "1.2.3.4:80"),
            ("<1.2.3.4:80>", "1.2.3.4:80"),
            ("1.2.3.4:80,", "1.2.3.4:80"),
            ("(1.2.3.4:80)", "1.2.3.4:80"),
        ],
    )
    def test_wrappers_are_removed(self, raw, expected):
        assert strip_token(raw) == expected

    def test_ipv6_brackets_are_preserved_when_a_port_follows(self):
        assert strip_token("[2001:db8::1]:8080") == "[2001:db8::1]:8080"


class TestParseHostPort:
    def test_bare_host_port(self):
        assert parse_host_port("8.8.8.8:8080") == ("8.8.8.8", 8080, None, None)

    def test_scheme_prefixed(self):
        assert parse_host_port("socks5://8.8.8.8:1080") == ("8.8.8.8", 1080, None, None)

    def test_credentials_are_extracted(self):
        assert parse_host_port("user:pass@8.8.8.8:8080") == ("8.8.8.8", 8080, "user", "pass")

    def test_username_without_password(self):
        assert parse_host_port("user@8.8.8.8:8080") == ("8.8.8.8", 8080, "user", None)

    def test_ipv6_with_port(self):
        # A routable address: 2001:db8::/32 is the RFC 3849 documentation range
        # and is correctly rejected as non-global (see the test below).
        assert parse_host_port("[2606:4700:4700::1111]:8080") == (
            "2606:4700:4700::1111",
            8080,
            None,
            None,
        )

    def test_documentation_range_ipv6_is_rejected(self):
        assert parse_host_port("[2001:db8::1]:8080") is None

    def test_protocol_relative_url_defaults_to_http(self):
        assert parse_host_port("//8.8.8.8:8080") == ("8.8.8.8", 8080, None, None)

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "# comment",
            "8.8.8.8",  # no port
            "8.8.8.8:0",  # invalid port
            "8.8.8.8:99999",  # invalid port
            "127.0.0.1:8080",  # loopback
            "192.168.1.1:3128",  # private
            "999.1.2.3:80",  # invalid octet
        ],
    )
    def test_rejected_inputs(self, raw):
        assert parse_host_port(raw) is None


class TestParseProxyToken:
    def test_scheme_hint_is_applied_to_a_bare_pair(self):
        candidate = parse_proxy_token("8.8.8.8:1080", SOCKS5_SOURCE)
        assert candidate is not None
        assert candidate.scheme == "socks5"
        assert candidate.source_name == "t_s5"
        assert candidate.source_priority == 2

    def test_explicit_scheme_overrides_the_hint(self):
        candidate = parse_proxy_token("socks4://8.8.8.8:1080", HTTP_SOURCE)
        assert candidate is not None
        assert candidate.scheme == "socks4"

    def test_https_url_is_treated_as_an_http_proxy(self):
        candidate = parse_proxy_token("https://8.8.8.8:443", HTTP_SOURCE)
        assert candidate is not None
        assert candidate.scheme == "http"

    @pytest.mark.parametrize("raw", ["", "   ", "# note", "garbage", "ftp://8.8.8.8:21"])
    def test_junk_yields_none(self, raw):
        assert parse_proxy_token(raw, HTTP_SOURCE) is None


class TestParseSampleCandidates:
    def test_counts_distinct_entries(self):
        text = "1.1.1.1:80\n2.2.2.2:80\n3.3.3.3:80\n"
        assert parse_sample_candidates(text, HTTP_SOURCE, 10) == 3

    def test_duplicates_are_not_double_counted(self):
        assert parse_sample_candidates("1.1.1.1:80 1.1.1.1:80", HTTP_SOURCE, 10) == 1

    def test_stops_once_the_target_is_reached(self):
        text = "\n".join(f"1.1.1.{i}:80" for i in range(1, 50))
        assert parse_sample_candidates(text, HTTP_SOURCE, 5) == 5

    def test_scheme_prefixed_lists_are_recognised(self):
        # proxifly, Argh94 and gfpcom all publish this shape.
        text = "http://1.1.1.1:80\nhttp://2.2.2.2:8080\n"
        assert parse_sample_candidates(text, HTTP_SOURCE, 10) == 2


class TestProxyCandidate:
    def test_url_without_auth(self):
        assert ProxyCandidate("http", "1.2.3.4", 80).proxy_url == "http://1.2.3.4:80"

    def test_url_with_auth_is_percent_encoded(self):
        candidate = ProxyCandidate("http", "1.2.3.4", 80, "u ser", "p@ss")
        assert candidate.proxy_url == "http://u%20ser:p%40ss@1.2.3.4:80"

    def test_ipv6_url_is_bracketed(self):
        assert ProxyCandidate("socks5", "2001:db8::1", 1080).proxy_url == "socks5://[2001:db8::1]:1080"

    def test_key_ignores_source_metadata(self):
        a = ProxyCandidate("http", "1.2.3.4", 80, source_name="a", source_priority=1)
        b = ProxyCandidate("http", "1.2.3.4", 80, source_name="b", source_priority=9)
        assert a.key == b.key


class TestFormatHost:
    def test_ipv4_is_untouched(self):
        assert format_host("1.2.3.4") == "1.2.3.4"

    def test_ipv6_gains_brackets(self):
        assert format_host("2001:db8::1") == "[2001:db8::1]"

    def test_already_bracketed_ipv6_is_left_alone(self):
        assert format_host("[2001:db8::1]") == "[2001:db8::1]"


class TestExtractIp:
    def test_from_json_ip_field(self):
        assert extract_ip('{"ip": "8.8.8.8"}') == "8.8.8.8"

    def test_from_json_origin_field(self):
        assert extract_ip('{"origin": "8.8.8.8"}') == "8.8.8.8"

    def test_from_plain_text(self):
        assert extract_ip("8.8.8.8\n") == "8.8.8.8"

    def test_ipv6_is_compressed(self):
        assert extract_ip('{"ip": "2001:0db8::0001"}') == "2001:db8::1"

    def test_missing_ip_returns_none(self):
        assert extract_ip("no address here") is None


class TestLooksLikeIpBlock:
    @pytest.mark.parametrize(
        "text",
        ["Your IP address is currently blocked", "Too Many Requests", "ACCESS DENIED"],
    )
    def test_block_phrases_are_detected(self, text):
        assert looks_like_ip_block(text) is True

    @pytest.mark.parametrize("text", ["", '{"valid": true}'])
    def test_normal_bodies_are_not_flagged(self, text):
        assert looks_like_ip_block(text) is False


class TestVies:
    def test_country_and_number_are_split(self):
        assert normalize_vies_probe_vat("BE0545786138") == ("BE", "0545786138")

    def test_separators_are_ignored(self):
        assert normalize_vies_probe_vat("be-0545 786138") == ("BE", "0545786138")

    def test_greece_uses_the_el_alias(self):
        assert normalize_vies_probe_vat("GR123456789")[0] == "EL"

    @pytest.mark.parametrize("value", ["", "B", "12", "1234567"])
    def test_malformed_ids_raise(self, value):
        with pytest.raises(ValueError):
            normalize_vies_probe_vat(value)

    def test_matching_response_is_accepted(self):
        body = '{"valid": true, "countryCode": "BE", "vatNumber": "0545786138"}'
        assert vies_vat_is_valid_response(body, "BE", "0545786138") is True

    def test_legacy_is_valid_field_is_accepted(self):
        body = '{"isValid": true, "countryCode": "BE", "vatNumber": "0545786138"}'
        assert vies_vat_is_valid_response(body, "BE", "0545786138") is True

    def test_a_different_vat_in_the_reply_is_rejected(self):
        # A proxy must not pass by echoing back someone else's VAT.
        body = '{"valid": true, "countryCode": "BE", "vatNumber": "9999999999"}'
        assert vies_vat_is_valid_response(body, "BE", "0545786138") is False

    @pytest.mark.parametrize(
        "body",
        ['{"valid": false, "countryCode": "BE", "vatNumber": "0545786138"}', "not json", "[]", ""],
    )
    def test_invalid_bodies_are_rejected(self, body):
        assert vies_vat_is_valid_response(body, "BE", "0545786138") is False
