"""
Tests for Phase 0 Foundation and Phase 1 / 1B Features:
- Scoring engine with diminishing returns and category caps
- Dedicated /about page with 18 checks and interactive elements
- Legal & Responsible use routes (/privacy, /terms)
- Canonical /assessments/<id> alias
- Simplified landing page structure
"""

import pytest
from cyberrecon.scanner.scoring import (
    compute_posture_score,
    calculate_posture_score,
    CHECK_REGISTRY,
    SCORE_VERSION,
    CATEGORY_CAPS,
    SEVERITY_TIERS,
)


def test_scoring_empty_findings_is_perfect_score():
    """A target with zero findings achieves 100 / Grade A."""
    result = compute_posture_score([])
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["score_version"] == SCORE_VERSION
    assert result["failed_checks"] == 0
    assert result["total_deduction"] == 0


def test_scoring_sample_profile_diminishing_returns():
    """
    Test sample scan profile: 3 Medium + 2 Low + 5 Info findings.
    Medium penalties: 8 + 6 + 4 = 18 pts.
    Low penalties: 3 + 2 = 5 pts.
    Info penalties: 0 pts.
    Total penalty: 23 pts.
    Final Score: 100 - 23 = 77 (Grade C).
    """
    findings = [
        {"id": "CR-002", "severity": "Medium", "category": "Transport Security"},
        {"id": "CR-003", "severity": "Medium", "category": "Browser Security"},
        {"id": "CR-004", "severity": "Medium", "category": "Browser Security"},
        {"id": "CR-005", "severity": "Low", "category": "Browser Security"},
        {"id": "CR-008", "severity": "Low", "category": "Browser Security"},
        {"id": "CR-006", "severity": "Info", "category": "Information Disclosure"},
        {"id": "CR-009", "severity": "Info", "category": "Browser Security"},
        {"id": "CR-013", "severity": "Info", "category": "Cross-Origin Security"},
        {"id": "CR-014", "severity": "Info", "category": "Cross-Origin Security"},
        {"id": "CR-015", "severity": "Info", "category": "Cross-Origin Security"},
    ]
    result = compute_posture_score(findings)
    assert result["score"] == 77
    assert result["grade"] == "C"
    assert result["score_version"] == SCORE_VERSION
    assert result["failed_checks"] == 10


def test_scoring_category_caps_enforced():
    """Transport Security cap is 25 points; excessive penalties must not exceed it."""
    findings = [
        {"id": "CR-001", "severity": "High", "category": "Transport Security"},    # 20
        {"id": "CR-002", "severity": "Medium", "category": "Transport Security"},  # 8 -> sum 28 capped to 25
    ]
    result = compute_posture_score(findings)
    assert result["category_penalties"]["Transport Security"] == 25
    assert result["score"] == 75
    assert result["grade"] == "C"


def test_no_check_in_registry_emits_critical():
    """Verify check registry does not contain any 'Critical' severity check."""
    for check_meta in CHECK_REGISTRY:
        assert check_meta["severity"] != "Critical", f"Check {check_meta['id']} has Critical severity!"
        assert check_meta["severity"] in ["High", "Medium", "Low", "Info"]


def test_about_page_renders_with_checks(client):
    """The /about page must load successfully with all 18 checks and scoring metadata."""
    response = client.get("/about")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Brand and title
    assert "Cyber<span>Recon</span>" in html
    assert "Methodology" in html

    # 18 checks present
    for check_meta in CHECK_REGISTRY:
        assert check_meta["id"] in html

    # Scoring and FAQ
    assert "How Scoring Works" in html
    assert SCORE_VERSION in html
    assert "SSRF Safeguards" in html
    assert "application/ld+json" in html
    assert "FAQPage" in html


def test_about_page_published_weights_match_code(client):
    """The /about page published weights must strictly match SEVERITY_TIERS in scoring.py."""
    response = client.get("/about")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Assert exact weights from scoring.py appear in the about page text
    high_pen = SEVERITY_TIERS["High"][0]
    med_pens = "/".join(str(p) for p in SEVERITY_TIERS["Medium"])
    low_pens = "/".join(str(p) for p in SEVERITY_TIERS["Low"])
    info_pen = SEVERITY_TIERS["Info"][0]

    assert f"High {high_pen} points" in html, f"Expected 'High {high_pen} points' in /about HTML"
    assert f"Medium {med_pens} points" in html, f"Expected 'Medium {med_pens} points' in /about HTML"
    assert f"Low {low_pens} points" in html, f"Expected 'Low {low_pens} points' in /about HTML"
    assert f"Info {info_pen} points" in html, f"Expected 'Info {info_pen} points' in /about HTML"


def test_privacy_and_terms_pages(client):
    """Privacy Policy and Terms of Responsible Use pages load with 200 OK."""
    res_privacy = client.get("/privacy")
    assert res_privacy.status_code == 200
    html_p = res_privacy.data.decode("utf-8")
    assert "Privacy Policy" in html_p
    assert "Strictly Passive Architecture" in html_p

    res_terms = client.get("/terms")
    assert res_terms.status_code == 200
    html_t = res_terms.data.decode("utf-8")
    assert "Terms of Responsible Use" in html_t
    assert "Mandatory Explicit Authorization" in html_t


def test_assessments_canonical_alias(authenticated_client):
    """Canonical alias /assessments/<scan_id> renders scan detail."""
    from tests.test_app_integration import build_fake_assessment
    from cyberrecon.storage import save_assessment

    with authenticated_client.session_transaction() as sess:
        user_id = sess["user_id"]

    fake_scan = build_fake_assessment("https://alias-test.local")
    fake_scan["metadata"]["scan_id"] = "CR-ALIAS01"
    save_assessment(fake_scan, user_id=user_id)

    response = authenticated_client.get("/assessments/CR-ALIAS01")
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "CR-ALIAS01" in html
