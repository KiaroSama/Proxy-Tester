"""Probe target construction, deadlines, and CLI wiring.

No network: every test here is pure logic. Live behaviour is covered by the
end-to-end run documented in the README.
"""

from __future__ import annotations

import argparse

import pytest

from proxy_tester.cli import _normalize_args, auto_per_source_limit, build_parser
from proxy_tester.constants import DEFAULT_OUTPUT, DEFAULT_PROBE_URLS, STRICT_IP_TIMEOUT_CAP
from proxy_tester.models import ProxyCandidate
from proxy_tester.probes import (
    build_probe_targets,
    build_vies_probe_request,
    candidate_hard_timeout,
    http_proxy_target_url,
    proxy_auth_header,
    response_status_ok,
)


class TestBuildProbeTargets:
    def test_generate_204_endpoints_demand_exactly_204(self):
        target = build_probe_targets(["http://cp.cloudflare.com/generate_204"])[0]
        assert target.expected_status == 204
        assert target.port == 80
        assert target.path_qs == "/generate_204"

    def test_other_endpoints_accept_any_success(self):
        assert build_probe_targets(["http://example.com/"])[0].expected_status is None

    def test_https_defaults_to_port_443(self):
        assert build_probe_targets(["https://example.com/x"])[0].port == 443

    def test_explicit_port_is_kept(self):
        assert build_probe_targets(["http://example.com:8080/"])[0].port == 8080

    def test_query_string_is_preserved(self):
        target = build_probe_targets(["https://api.ipify.org?format=json"])[0]
        assert target.path_qs.endswith("?format=json")

    def test_empty_path_becomes_root(self):
        assert build_probe_targets(["http://example.com"])[0].path_qs == "/"

    @pytest.mark.parametrize("url", ["ftp://example.com/", "not-a-url", "://x"])
    def test_unsupported_urls_raise(self, url):
        with pytest.raises(ValueError):
            build_probe_targets([url])

    def test_every_shipped_default_parses(self):
        targets = build_probe_targets(list(DEFAULT_PROBE_URLS))
        assert len(targets) == len(DEFAULT_PROBE_URLS)

    def test_defaults_span_more_than_one_provider(self):
        # Google 403s known proxy IPs; a single-provider list causes false negatives.
        hosts = {t.host for t in build_probe_targets(list(DEFAULT_PROBE_URLS))}
        assert len({h.split(".")[-2] for h in hosts}) >= 2


class TestResponseStatusOk:
    def test_204_endpoint_accepts_only_204(self):
        target = build_probe_targets(["http://cp.cloudflare.com/generate_204"])[0]
        assert response_status_ok(target, 204) is True
        assert response_status_ok(target, 200) is False

    @pytest.mark.parametrize("status,expected", [(200, True), (301, True), (404, False), (500, False)])
    def test_open_endpoint_accepts_2xx_and_3xx(self, status, expected):
        target = build_probe_targets(["http://example.com/"])[0]
        assert response_status_ok(target, status) is expected

    def test_missing_status_is_a_failure(self):
        assert response_status_ok(build_probe_targets(["http://example.com/"])[0], None) is False


class TestRequestBuilders:
    def test_default_port_is_omitted_from_the_absolute_url(self):
        target = build_probe_targets(["http://example.com/x"])[0]
        assert http_proxy_target_url(target) == "http://example.com/x"

    def test_non_default_port_is_included(self):
        target = build_probe_targets(["http://example.com:8080/x"])[0]
        assert http_proxy_target_url(target) == "http://example.com:8080/x"

    def test_no_auth_header_without_credentials(self):
        assert proxy_auth_header(ProxyCandidate("http", "1.2.3.4", 80)) == ""

    def test_basic_auth_header_is_base64(self):
        header = proxy_auth_header(ProxyCandidate("http", "1.2.3.4", 80, "user", "pass"))
        assert header == "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"

    def test_vies_request_is_a_well_formed_post(self):
        host, port, vat, request = build_vies_probe_request("BE0545786138")
        assert host == "ec.europa.eu"
        assert port == 443
        assert vat == "BE0545786138"
        assert request.startswith(b"POST ")
        assert b"Content-Type: application/json" in request
        assert b'"countryCode":"BE"' in request
        # A wrong Content-Length would hang the server.
        body = request.split(b"\r\n\r\n", 1)[1]
        declared = int(
            next(
                line.split(b":")[1]
                for line in request.split(b"\r\n")
                if line.lower().startswith(b"content-length")
            )
        )
        assert declared == len(body)


class TestCandidateHardTimeout:
    def _args(self, **kw):
        base = {"timeout": 6.0, "stability_checks": 1, "require_different_ip": False}
        base.update(kw)
        return argparse.Namespace(**base)

    def test_always_positive(self):
        assert candidate_hard_timeout(self._args()) > 0

    def test_more_rounds_cost_more_time(self):
        assert candidate_hard_timeout(self._args(stability_checks=3)) > candidate_hard_timeout(
            self._args(stability_checks=1)
        )

    def test_strict_ip_mode_adds_a_bounded_amount(self):
        plain = candidate_hard_timeout(self._args())
        strict = candidate_hard_timeout(self._args(require_different_ip=True))
        assert plain < strict <= plain + STRICT_IP_TIMEOUT_CAP + 0.01

    def test_bound_stays_finite_for_a_large_timeout(self):
        assert candidate_hard_timeout(self._args(timeout=60.0, stability_checks=5)) < 400


class TestCliDefaults:
    def test_output_defaults_into_the_output_directory(self):
        args = build_parser().parse_args([])
        assert args.output == DEFAULT_OUTPUT
        assert args.output.startswith("output/")

    def test_fast_reachability_is_the_default_probe(self):
        # The VIES probe is far slower; it must be opt-in.
        assert build_parser().parse_args([]).vies_check is False

    def test_vies_check_can_be_enabled(self):
        assert build_parser().parse_args(["--vies-check"]).vies_check is True

    def test_test_url_is_repeatable(self):
        args = build_parser().parse_args(
            ["--test-url", "http://a.example/", "--test-url", "http://b.example/"]
        )
        assert args.test_urls == ["http://a.example/", "http://b.example/"]

    @pytest.mark.parametrize(
        "field,given,expected",
        [
            ("workers", "-5", 1),
            ("timeout", "0.01", 0.5),
            ("stability_checks", "0", 1),
            ("stability_timeout_factor", "9", 1.0),
            ("stability_timeout_factor", "0.01", 0.2),
            ("tail_drain_timeout", "999", 5.0),
            ("tail_empty_timeout", "-3", 0.0),
        ],
    )
    def test_out_of_range_values_are_clamped(self, field, given, expected):
        flag = "--" + field.replace("_", "-")
        args = build_parser().parse_args([flag, given])
        args.need = 10
        _normalize_args(args)
        assert getattr(args, field) == expected

    def test_health_timeout_never_exceeds_the_source_timeout(self):
        args = build_parser().parse_args(["--source-timeout", "2", "--source-health-timeout", "30"])
        args.need = 10
        _normalize_args(args)
        assert args.source_health_timeout <= args.source_timeout

    def test_auto_per_source_limit_is_derived_from_need(self):
        args = build_parser().parse_args([])
        args.need = 10
        _normalize_args(args)
        assert args.per_source_limit == auto_per_source_limit(10)

    @pytest.mark.parametrize("need,expected", [(1, 1200), (10, 1200), (100, 4500), (10_000, 6000)])
    def test_auto_per_source_limit_stays_within_bounds(self, need, expected):
        assert auto_per_source_limit(need) == expected
