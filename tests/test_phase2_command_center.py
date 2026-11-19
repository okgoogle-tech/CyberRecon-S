"""
Tests for Phase 2: Security Command Center
- REST API endpoints: /api/dashboard/summary, /api/dashboard/timeseries, /api/dashboard/matrix
- Cross-filtering by range, target, severity
- User data isolation in APIs
- Dev-only demo seeder production guard
- Recommended next actions scoring calculation
"""

import os
import pytest
from datetime import datetime, timezone
import cyberrecon.storage as storage
from tests.test_dashboard_command_center import make_assessment_data


def test_api_dashboard_endpoints_require_auth(client):
    """Unauthenticated requests to dashboard APIs must return 401 Unauthorized JSON."""
    res_summary = client.get("/api/dashboard/summary")
    assert res_summary.status_code == 401
    assert "error" in res_summary.get_json()

    res_ts = client.get("/api/dashboard/timeseries")
    assert res_ts.status_code == 401
    assert "error" in res_ts.get_json()

    res_mat = client.get("/api/dashboard/matrix")
    assert res_mat.status_code == 401
    assert "error" in res_mat.get_json()


def test_api_dashboard_parameter_validation(authenticated_client):
    """Invalid range, severity, or malformed target parameters return 400 Bad Request."""
    # Invalid range
    res_range = authenticated_client.get("/api/dashboard/summary?range=invalid_999")
    assert res_range.status_code == 400
    assert "Invalid date range parameter" in res_range.get_json()["error"]

    # Invalid severity (e.g. Critical which CyberRecon does not emit)
    res_sev = authenticated_client.get("/api/dashboard/summary?severity=Critical")
    assert res_sev.status_code == 400
    assert "Invalid severity filter parameter" in res_sev.get_json()["error"]

    # Malformed target (injection or control chars)
    res_target = authenticated_client.get("/api/dashboard/summary?target=bad<script>injection")
    assert res_target.status_code == 400
    assert "Invalid target filter parameter" in res_target.get_json()["error"]

    # Timeseries endpoint invalid range
    res_ts_bad = authenticated_client.get("/api/dashboard/timeseries?range=not_a_range")
    assert res_ts_bad.status_code == 400


def test_api_dashboard_summary_structure(app, authenticated_client):
    """Authenticated user receives structured dashboard summary."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-P2-01", target="https://api-test.local")
        storage.save_assessment(data, user["id"])

    response = authenticated_client.get("/api/dashboard/summary")
    assert response.status_code == 200
    json_data = response.get_json()

    assert "posture_score" in json_data
    assert "posture_grade" in json_data
    assert "severity_donut" in json_data
    assert "category_breakdown" in json_data
    assert "recommended_actions" in json_data
    assert "activity_calendar" in json_data
    assert "resolved_vs_new" in json_data
    assert "monitored_targets" in json_data

    # Severity donut must never emit or contain 'Critical'
    assert "Critical" not in json_data["severity_donut"]
    assert "High" in json_data["severity_donut"]
    assert "Medium" in json_data["severity_donut"]


def test_api_dashboard_timeseries(app, authenticated_client):
    """Timeseries endpoint returns chronological scores and points."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-P2-02", target="https://timeseries.local")
        storage.save_assessment(data, user["id"])

    response = authenticated_client.get("/api/dashboard/timeseries")
    assert response.status_code == 200
    json_data = response.get_json()

    assert "timeseries" in json_data
    assert len(json_data["timeseries"]) > 0
    pt = json_data["timeseries"][0]
    assert "score" in pt
    assert "grade" in pt
    assert "target" in pt


def test_api_dashboard_matrix(app, authenticated_client):
    """Matrix endpoint returns 18 checks and targets grid."""
    with app.app_context():
        user = storage.get_user_by_email("test@example.com")
        data = make_assessment_data("CR-P2-03", target="https://matrix-target.local")
        storage.save_assessment(data, user["id"])

    response = authenticated_client.get("/api/dashboard/matrix")
    assert response.status_code == 200
    json_data = response.get_json()

    assert "checks" in json_data
    assert len(json_data["checks"]) == 18
    assert "matrix" in json_data
    assert "https://matrix-target.local" in json_data["matrix"]


def test_api_dashboard_user_isolation(app, client, register_user, login_user):
    """User A cannot access User B's analytics data via API endpoints."""
    # Create User A with scan
    register_user(client, username="isolated_a", email="user_a@test.local", password="Password123")
    login_user(client, email="user_a@test.local", password="Password123")
    with app.app_context():
        user_a = storage.get_user_by_email("user_a@test.local")
        data_a = make_assessment_data("CR-ISO-A", target="https://secret-a.corp")
        storage.save_assessment(data_a, user_a["id"])

    # Logout User A
    client.post("/logout")

    # Create User B
    register_user(client, username="isolated_b", email="user_b@test.local", password="Password123")
    login_user(client, email="user_b@test.local", password="Password123")
    with app.app_context():
        user_b = storage.get_user_by_email("user_b@test.local")
        data_b = make_assessment_data("CR-ISO-B", target="https://public-b.corp")
        storage.save_assessment(data_b, user_b["id"])

    # Inspect User B API output
    res_b = client.get("/api/dashboard/summary")
    assert res_b.status_code == 200
    json_b = res_b.get_json()

    # User B should only see secret B, never secret A
    targets = [t["target"] for t in json_b.get("monitored_targets", [])]
    assert "https://public-b.corp" in targets
    assert "https://secret-a.corp" not in targets

    # Check timeseries isolation
    res_ts = client.get("/api/dashboard/timeseries")
    ts_targets = [pt["target"] for pt in res_ts.get_json().get("timeseries", [])]
    assert "https://secret-a.corp" not in ts_targets

    # Check cross-filtering isolation: User B queries specifically for User A's target
    res_filtered = client.get("/api/dashboard/summary?target=https://secret-a.corp")
    assert res_filtered.status_code == 200
    json_filtered = res_filtered.get_json()
    assert json_filtered["overview"]["total_scans"] == 0
    assert "https://secret-a.corp" not in [t["target"] for t in json_filtered.get("monitored_targets", [])]

    # Check matrix isolation with target filter
    res_matrix = client.get("/api/dashboard/matrix?target=https://secret-a.corp")
    assert res_matrix.status_code == 200
    assert "https://secret-a.corp" not in res_matrix.get_json().get("matrix", {})


def test_seed_demo_production_guard():
    """seed_demo.py must abort if CYBERRECON_ENV == 'production'."""
    from scripts.seed_demo import check_production_guard

    os.environ["CYBERRECON_ENV"] = "production"
    try:
        with pytest.raises(SystemExit) as excinfo:
            check_production_guard()
        assert excinfo.value.code == 1
    finally:
        os.environ.pop("CYBERRECON_ENV", None)


def test_seed_demo_reset_flag_only_touches_demo_user(app):
    """Calling seed_demo_data(reset_only=True) deletes only demo user rows, not real accounts."""
    from scripts.seed_demo import seed_demo_data, DEMO_EMAIL
    from tests.test_app_integration import build_fake_assessment

    with app.app_context():
        # Ensure a regular user exists and has a scan
        real_user = storage.get_user_by_email("test@example.com")
        if not real_user:
            storage.create_user("real_tester", "test@example.com", "hash")
            real_user = storage.get_user_by_email("test@example.com")
        
        real_scan = build_fake_assessment("https://real-user-asset.org")
        real_scan["metadata"]["scan_id"] = "CR-REAL-KEEP"
        storage.save_assessment(real_scan, user_id=real_user["id"])

        # Run reset_only
        seed_demo_data(reset_only=True)

        # Confirm real user's scan is completely intact
        real_history = storage.get_scan_history(real_user["id"])
        real_ids = [s["scan_id"] for s in real_history]
        assert "CR-REAL-KEEP" in real_ids

        # Confirm demo user has 0 scans
        demo_user = storage.get_user_by_email(DEMO_EMAIL)
        if demo_user:
            demo_history = storage.get_scan_history(demo_user["id"])
            assert len(demo_history) == 0
