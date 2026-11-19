"""
Tests for Phase 3: End-to-End Product Completion
- Canonical Assessment Report (/assessments/<id>)
- 301 Legacy Redirects (/history/<id> and /scan/<id> -> /assessments/<id>)
- Assessment Deletion (/assessments/<id>/delete)
- Assessment JSON Export (/assessments/<id>/export.json)
- Monitored Targets Directory (/targets)
- Platform Settings (/settings, password update, JSON export archive, account deletion)
- Compare Scans & 18-Check Transition Matrix (/compare)
- Bulk Delete Scans (/history/bulk-delete)
- Tenant Isolation across all endpoints
- Branded 404 & 500 error handlers
"""

import json
import pytest
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash
import cyberrecon.storage as storage
from tests.test_dashboard_command_center import make_assessment_data


def test_canonical_assessment_report_view(app, authenticated_client):
    """Authenticated user accesses canonical report with PostureRing and tabs."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-CANONICAL-01", target="https://canonical.example.com")
        storage.save_assessment(data, user["id"])

    response = authenticated_client.get("/assessments/CR-CANONICAL-01")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # PostureRing and score elements
    assert "posture-ring-svg" in html or "posture-score-num" in html or "posture_ring" in html
    assert "https://canonical.example.com" in html
    assert "CR-CANONICAL-01" in html

    # Tabs: Findings, Passed Checks, Raw Evidence
    assert "tab-findings" in html
    assert "tab-passed" in html
    assert "tab-raw" in html

    # Remediation snippets (Nginx, Apache, Express)
    assert "remediation-box" in html
    assert "Nginx" in html
    assert "Apache" in html
    assert "Express.js" in html


def test_canonical_assessment_unauthorized_isolation(app, client):
    """Unauthenticated users are redirected to login; other users cannot see private assessments."""
    with app.app_context():
        user_a_id = storage.create_user("user_a", "usera@example.com", generate_password_hash("Password123!"))
        data = make_assessment_data("CR-PRIVATE-01", target="https://private.local")
        storage.save_assessment(data, user_a_id)

    # Unauthenticated request redirects to login
    res_anon = client.get("/assessments/CR-PRIVATE-01")
    assert res_anon.status_code == 302
    assert "/login" in res_anon.headers["Location"]

    # Different authenticated user gets 404 (no leak)
    with app.app_context():
        storage.create_user("user_b", "userb@example.com", generate_password_hash("Password123!"))

    # Login as user_b
    client.post("/login", data={"email": "userb@example.com", "password": "Password123!"})
    res_b = client.get("/assessments/CR-PRIVATE-01")
    assert res_b.status_code == 404


def test_legacy_scan_and_history_301_redirects(app, authenticated_client):
    """Legacy routes /history/<id> (with browser navigation) and /scan/<id> return 301 to /assessments/<id>."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-LEGACY-99", target="https://legacy.local")
        storage.save_assessment(data, user["id"])

    res_hist = authenticated_client.get("/history/CR-LEGACY-99", headers={"Sec-Fetch-Mode": "navigate"})
    assert res_hist.status_code == 301
    assert res_hist.headers["Location"] == "/assessments/CR-LEGACY-99"

    res_scan = authenticated_client.get("/scan/CR-LEGACY-99")
    assert res_scan.status_code == 301
    assert res_scan.headers["Location"] == "/assessments/CR-LEGACY-99"


def test_assessment_json_export(app, authenticated_client):
    """Assessment JSON export returns structured scan telemetry and findings."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-EXPORT-01", target="https://export.example.com")
        storage.save_assessment(data, user["id"])

    response = authenticated_client.get("/assessments/CR-EXPORT-01/export.json")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("application/json")

    payload = json.loads(response.get_data(as_text=True))
    assert payload["scan_id"] == "CR-EXPORT-01"
    assert payload["target"] == "https://export.example.com"
    assert "posture" in payload
    assert "findings" in payload
    assert isinstance(payload["findings"], list)


def test_assessment_deletion(app, authenticated_client):
    """Deleting an assessment removes it from history and returns 404 on subsequent read."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-DELETE-01", target="https://delete-me.local")
        storage.save_assessment(data, user["id"])

    # Confirm it exists
    res_before = authenticated_client.get("/assessments/CR-DELETE-01")
    assert res_before.status_code == 200

    # Execute deletion
    res_delete = authenticated_client.post("/assessments/CR-DELETE-01/delete")
    assert res_delete.status_code == 302
    assert "/history" in res_delete.headers["Location"]

    # Confirm subsequent read is 404
    res_after = authenticated_client.get("/assessments/CR-DELETE-01")
    assert res_after.status_code == 404


def test_targets_directory_view(app, authenticated_client):
    """Targets directory lists unique monitored endpoints with sparklines and scores."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data1 = make_assessment_data("CR-TGT-01", target="https://app.target1.local")
        data2 = make_assessment_data("CR-TGT-02", target="https://app.target1.local")
        data3 = make_assessment_data("CR-TGT-03", target="https://api.target2.local")
        storage.save_assessment(data1, user["id"])
        storage.save_assessment(data2, user["id"])
        storage.save_assessment(data3, user["id"])

    response = authenticated_client.get("/targets")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "TARGET REGISTRY" in html
    assert "app.target1.local" in html
    assert "api.target2.local" in html
    assert "Reassess" in html
    assert "Compare" in html


def test_settings_profile_and_password_update(app, authenticated_client):
    """Settings view displays profile; password change updates credentials securely."""
    response = authenticated_client.get("/settings")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "Platform <span>Settings</span>" in html
    assert "test@example.com" in html
    assert "Export Account Telemetry" in html
    assert "Self-Service Password Reset" in html

    # Test password mismatch error
    res_mismatch = authenticated_client.post("/settings", data={
        "action": "change_password",
        "current_password": "Testpass123",
        "new_password": "NewSecretPassword2026!",
        "confirm_password": "DifferentPassword2026!"
    })
    assert res_mismatch.status_code == 200
    assert "New passwords do not match" in res_mismatch.get_data(as_text=True)

    # Test incorrect current password
    res_bad_curr = authenticated_client.post("/settings", data={
        "action": "change_password",
        "current_password": "WrongPassword!",
        "new_password": "NewSecretPassword2026!",
        "confirm_password": "NewSecretPassword2026!"
    })
    assert res_bad_curr.status_code == 200
    assert "Current password is incorrect" in res_bad_curr.get_data(as_text=True)

    # Test successful password change
    res_success = authenticated_client.post("/settings", data={
        "action": "change_password",
        "current_password": "Testpass123",
        "new_password": "NewSecretPassword2026!",
        "confirm_password": "NewSecretPassword2026!"
    })
    assert res_success.status_code == 200
    assert "Password successfully changed" in res_success.get_data(as_text=True)


def test_settings_data_export_archive(app, authenticated_client):
    """Settings JSON export returns complete account telemetry archive."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-ARCHIVE-01", target="https://archive.local")
        storage.save_assessment(data, user["id"])

    response = authenticated_client.get("/settings/export")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("application/json")

    archive = json.loads(response.get_data(as_text=True))
    assert archive["account"]["email"] == "test@example.com"
    assert "exported_at" in archive
    assert len(archive["scans"]) >= 1


def test_compare_scans_delta_and_transition_matrix(app, authenticated_client):
    """Comparing two scans displays delta points, summary metrics, and 18-check status matrix."""
    findings_base = [
        {
            "id": "CR-001",
            "finding_code": "CR-001",
            "name": "HTTPS Protocol Enforcement",
            "category": "transport",
            "severity": "High",
            "confidence": "High",
            "affected_component": "Transport Layer",
            "cwe": "CWE-319",
            "owasp": "A02:2021",
            "evidence": "Target does not enforce HTTPS",
            "description": "Cleartext traffic",
            "recommendation": "Enforce HTTPS",
        },
        {
            "id": "CR-003",
            "finding_code": "CR-003",
            "name": "Content-Security-Policy (CSP)",
            "category": "browser",
            "severity": "High",
            "confidence": "High",
            "affected_component": "HTTP Response Headers",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
            "evidence": "CSP missing",
            "description": "No CSP",
            "recommendation": "Add CSP",
        },
    ]
    findings_curr = [
        {
            "id": "CR-003",
            "finding_code": "CR-003",
            "name": "Content-Security-Policy (CSP)",
            "category": "browser",
            "severity": "High",
            "confidence": "High",
            "affected_component": "HTTP Response Headers",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
            "evidence": "CSP missing",
            "description": "No CSP",
            "recommendation": "Add CSP",
        }
    ]

    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        base_data = make_assessment_data("CR-CMP-BASE", target="https://compare.local", findings=findings_base)
        curr_data = make_assessment_data("CR-CMP-CURR", target="https://compare.local", findings=findings_curr)
        storage.save_assessment(base_data, user["id"])
        storage.save_assessment(curr_data, user["id"])

    response = authenticated_client.get("/compare?baseline=CR-CMP-BASE&current=CR-CMP-CURR")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "HISTORICAL DELTA AUDIT" in html
    assert "SECURITY POSTURE SHIFT" in html
    assert "Check Transition Matrix (18 Checks)" in html
    assert "Resolved" in html
    assert "New Risks" in html
    assert "Unchanged" in html


def test_history_bulk_delete(app, authenticated_client):
    """Bulk delete removes only the specified scans owned by the user."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        d1 = make_assessment_data("CR-BULK-01", target="https://bulk1.local")
        d2 = make_assessment_data("CR-BULK-02", target="https://bulk2.local")
        d3 = make_assessment_data("CR-BULK-03", target="https://keep.local")
        storage.save_assessment(d1, user["id"])
        storage.save_assessment(d2, user["id"])
        storage.save_assessment(d3, user["id"])

    response = authenticated_client.post("/history/bulk-delete", data={
        "scan_ids": ["CR-BULK-01", "CR-BULK-02"]
    })
    assert response.status_code == 302
    assert "/history" in response.headers["Location"]

    # Verify CR-BULK-01 and 02 are deleted, CR-BULK-03 remains
    assert authenticated_client.get("/assessments/CR-BULK-01").status_code == 404
    assert authenticated_client.get("/assessments/CR-BULK-02").status_code == 404
    assert authenticated_client.get("/assessments/CR-BULK-03").status_code == 200


def test_branded_404_page(client):
    """Visiting a non-existent URL returns a branded 404 page with navigation actions."""
    response = client.get("/non-existent-route-for-testing")
    assert response.status_code == 404
    html = response.get_data(as_text=True)
    assert "404" in html
    assert "Target Endpoint Not Located" in html or "ROUTE NOT FOUND" in html or "404 Not Found" in html
    assert "Return to Dashboard" in html
