"""
Unit and integration tests for HTTP and HTTPS target handling, SSRF guards,
and HTTP-only posture score capping.
"""

import pytest
from cyberrecon.scanner.target import (
    normalize_target,
    validate_network_destination,
    UnsafeTargetError,
    ALLOWED_PORTS,
)
from cyberrecon.scanner.scoring import (
    calculate_posture_score,
    SCORE_VERSION,
)
from cyberrecon.scanner.reconnaissance import (
    build_success_result,
    build_failure_result,
)


def test_normalize_target_supports_http_and_https():
    assert normalize_target("http://example.com") == "http://example.com"
    assert normalize_target("https://example.com") == "https://example.com"
    # Bare hostname defaults to https
    assert normalize_target("example.com") == "https://example.com"


def test_normalize_target_allowed_ports():
    assert normalize_target("http://example.com:80") == "http://example.com:80"
    assert normalize_target("https://example.com:443") == "https://example.com:443"
    assert normalize_target("http://example.com:8080") == "http://example.com:8080"
    assert normalize_target("https://example.com:8443") == "https://example.com:8443"


def test_normalize_target_disallowed_ports_rejected():
    with pytest.raises(ValueError, match="is not permitted"):
        normalize_target("https://example.com:22")
    with pytest.raises(ValueError, match="is not permitted"):
        normalize_target("http://example.com:8000")
    with pytest.raises(ValueError, match="is not permitted"):
        normalize_target("https://example.com:3389")


def test_normalize_target_rejects_non_http_schemes():
    with pytest.raises(ValueError, match="Only HTTP and HTTPS targets"):
        normalize_target("ftp://example.com")
    with pytest.raises(ValueError, match="Only HTTP and HTTPS targets"):
        normalize_target("file:///etc/passwd")
    with pytest.raises(ValueError, match="Only HTTP and HTTPS targets"):
        normalize_target("gopher://example.com")


def test_normalize_target_rejects_credentials_and_strips_fragment():
    with pytest.raises(ValueError, match="credentials"):
        normalize_target("https://admin:secret@example.com")
    assert normalize_target("http://example.com/page#top") == "http://example.com/page"


def test_ssrf_destination_validation_blocks_private_and_loopback(monkeypatch):
    monkeypatch.setenv("CYBERRECON_ALLOW_PRIVATE_TARGETS", "0")
    with pytest.raises(UnsafeTargetError):
        validate_network_destination("http://127.0.0.1")
    with pytest.raises(UnsafeTargetError):
        validate_network_destination("http://localhost")
    with pytest.raises(UnsafeTargetError):
        validate_network_destination("http://10.0.0.1")
    with pytest.raises(UnsafeTargetError):
        validate_network_destination("http://192.168.1.1")
    with pytest.raises(UnsafeTargetError):
        validate_network_destination("http://169.254.169.254")


def test_http_only_scoring_cap_max_grade_d():
    # Target with perfect findings (0 issues) on HTTPS gets 100 / Grade A
    https_result = calculate_posture_score([], is_http=False)
    assert https_result["score"] == 100
    assert https_result["grade"] == "A"
    assert https_result["na_checks"] == 0

    # Same findings on unencrypted HTTP: capped at Grade D (score max 69) and CR-002 marked NA
    http_result = calculate_posture_score([], is_http=True)
    assert http_result["score"] == 69
    assert http_result["grade"] == "D"
    assert "CR-002" in http_result["na_check_ids"]
    assert http_result["is_unencrypted"] is True


def test_scoring_legacy_v1_1_backward_compatibility():
    # Legacy version ignores HTTP cap
    result = calculate_posture_score([], is_http=True, version="v1.1-diminishing")
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["score_version"] == "v1.1-diminishing"


def test_recon_records_requested_and_effective_schemes():
    # Simulated response object
    class DummyResponse:
        status_code = 200
        headers = {}
        raw = None
        text = "<html><head><title>Test</title></head><body>OK</body></html>"

    req_result = {
        "response": DummyResponse(),
        "elapsed_ms": 120,
        "redirect_count": 1,
        "final_url": "http://example.com/login",
        "resolved_addresses": ["93.184.216.34"],
    }
    # HTTPS requested, but redirected/downgraded to HTTP
    res = build_success_result("https://example.com", req_result, fallback_used=False)
    assert res["requested_scheme"] == "https"
    assert res["effective_scheme"] == "http"
    assert res["scheme_downgrade"] is True
    assert res["https_enabled"] is False
