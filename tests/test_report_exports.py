"""
Tests for Assessment Export Formats:
PDF, JSON, CSV, HTML
- Validates 200 OK and Content-Type for owner
- Validates 404 for unauthorized tenant
- Validates 302 redirect for anonymous visitor
- Validates CSV formula injection defense
- Validates filename pattern cyberrecon-<host>-<scanid>-<yyyymmdd>.<ext>
"""

import pytest
from werkzeug.security import generate_password_hash
import cyberrecon.storage as storage
from tests.test_dashboard_command_center import make_assessment_data


@pytest.fixture
def seeded_export_user(app):
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        if not user:
            user_id = storage.create_user("testuser", "test@example.com", generate_password_hash("Password123!"))
        else:
            user_id = user["id"]

        data = make_assessment_data("CR-EXPORT-01", target="https://export-target.local")
        # Add finding with formula injection payload to test escaping
        data["findings"].append({
            "finding_code": "CR-099",
            "name": "=cmd|'/C calc'!A0",
            "category": "Testing",
            "severity": "Low",
            "status": "FAIL",
            "cwe": "CWE-123",
            "recommendation": "@SUM(1+1)",
        })
        storage.save_assessment(data, user_id)
        return user_id


def test_export_pdf_owner_success(app, authenticated_client, seeded_export_user):
    """Owner receives 200 OK, application/pdf, and formatted filename."""
    res = authenticated_client.get("/assessments/CR-EXPORT-01/export.pdf")
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "application/pdf"
    assert "attachment; filename=\"cyberrecon-export-target.local-CR-EXPORT-01-" in res.headers["Content-Disposition"]
    assert res.headers["Content-Disposition"].endswith('.pdf"')
    assert res.data.startswith(b"%PDF-1.4")


def test_export_json_owner_success(app, authenticated_client, seeded_export_user):
    """Owner receives 200 OK, application/json, and valid payload."""
    res = authenticated_client.get("/assessments/CR-EXPORT-01/export.json")
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "application/json"
    assert "attachment; filename=\"cyberrecon-export-target.local-CR-EXPORT-01-" in res.headers["Content-Disposition"]
    data = res.get_json()
    assert data["scan_id"] == "CR-EXPORT-01"
    assert "posture" in data
    assert "findings" in data


def test_export_csv_owner_success_and_formula_escape(app, authenticated_client, seeded_export_user):
    """Owner receives 200 OK, text/csv, proper headers, and formula injection escaping."""
    res = authenticated_client.get("/assessments/CR-EXPORT-01/export.csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["Content-Type"]
    assert "attachment; filename=\"cyberrecon-export-target.local-CR-EXPORT-01-" in res.headers["Content-Disposition"]

    csv_text = res.get_data(as_text=True)
    lines = [line.strip() for line in csv_text.splitlines() if line.strip()]
    header_line = lines[0]
    assert "Check ID" in header_line
    assert "Remediation Summary" in header_line

    # Check that formula payload =cmd was escaped with single quote
    assert "'=cmd" in csv_text
    assert "'@SUM" in csv_text


def test_export_html_owner_success(app, authenticated_client, seeded_export_user):
    """Owner receives 200 OK, text/html, and formatted filename."""
    res = authenticated_client.get("/assessments/CR-EXPORT-01/export.html")
    assert res.status_code == 200
    assert "text/html" in res.headers["Content-Type"]
    assert "attachment; filename=\"cyberrecon-export-target.local-CR-EXPORT-01-" in res.headers["Content-Disposition"]
    assert "CyberRecon" in res.get_data(as_text=True)


def test_export_unauthenticated_redirects(app, client, seeded_export_user):
    """Unauthenticated access to any export format redirects to login."""
    for fmt in ["pdf", "json", "csv", "html"]:
        res = client.get(f"/assessments/CR-EXPORT-01/export.{fmt}")
        assert res.status_code == 302
        assert "/login" in res.headers["Location"]


def test_export_tenant_isolation_returns_404(app, client, seeded_export_user):
    """A different user receives 404 when requesting another user's scan export."""
    with app.app_context():
        storage.create_user("attacker", "attacker@example.com", generate_password_hash("Password123!"))

    client.post("/login", data={"email": "attacker@example.com", "password": "Password123!"})
    for fmt in ["pdf", "json", "csv", "html"]:
        res = client.get(f"/assessments/CR-EXPORT-01/export.{fmt}")
        assert res.status_code == 404
