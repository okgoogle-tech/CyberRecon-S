"""
Dev-only realistic assessment data seeder for CyberRecon Command Center.

Creates a dedicated demo account with 30+ days of realistic assessment history
across 3+ targets, exercising all 18 checks, category breakdowns, and posture trends.
Strictly disabled if CYBERRECON_ENV == "production".
"""

import os
import sys
import sqlite3
import random
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from werkzeug.security import generate_password_hash
from cyberrecon.storage import (
    get_connection,
    initialize_database,
    create_user,
    get_user_by_email,
    save_assessment,
)
from cyberrecon.scanner.scoring import CHECK_REGISTRY, calculate_posture_score

DEMO_EMAIL = "demo@cyberrecon.local"
DEMO_USERNAME = "demo_auditor"
DEMO_PASSWORD = "DemoAuditor2026!"

TARGETS = [
    {
        "url": "https://app.example.com",
        "domain": "app.example.com",
        "base_failing": ["CR-003", "CR-005", "CR-009"], # Initial: CSP, X-Content-Type, Referrer
        "improved_failing": ["CR-005"],                 # Later improved to Grade A
    },
    {
        "url": "https://api.secure-gateway.io",
        "domain": "api.secure-gateway.io",
        "base_failing": ["CR-001", "CR-002", "CR-012", "CR-016"], # Missing TLS/HSTS, Wildcard CORS, Cookie
        "improved_failing": ["CR-002", "CR-012"],                 # Added TLS later
    },
    {
        "url": "https://portal.internal-corp.dev",
        "domain": "portal.internal-corp.dev",
        "base_failing": ["CR-004", "CR-008", "CR-010", "CR-017", "CR-018"], # X-Frame, Perms, Cache, HttpOnly, SameSite
        "improved_failing": ["CR-004", "CR-010"],
    },
]

def check_production_guard():
    env = os.environ.get("CYBERRECON_ENV", "").lower()
    prod_flag = os.environ.get("PRODUCTION", "0")
    if env in ("production", "prod") or prod_flag == "1":
        print("[ERROR] seed_demo.py cannot be executed in production environments!")
        sys.exit(1)

def reset_demo_user():
    """Reset and delete only the demo user's assessment scans."""
    check_production_guard()
    initialize_database()
    user = get_user_by_email(DEMO_EMAIL)
    if not user:
        print(f"Demo user {DEMO_EMAIL} does not exist. Nothing to reset.")
        return 0

    user_id = user["id"]
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM findings WHERE scan_database_id IN (SELECT id FROM scans WHERE user_id = ?)",
            (user_id,)
        )
        cursor = conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        deleted_count = cursor.rowcount
        conn.commit()

    print(f"Successfully deleted {deleted_count} demo scan records for {DEMO_EMAIL}. Dev account was untouched.")
    return deleted_count


def seed_demo_data(reset_only=False):
    check_production_guard()
    initialize_database()

    if reset_only:
        return reset_demo_user()

    print("[1/4] Ensuring demo user exists...")
    user = get_user_by_email(DEMO_EMAIL)
    if not user:
        create_user(DEMO_USERNAME, DEMO_EMAIL, generate_password_hash(DEMO_PASSWORD))
        user = get_user_by_email(DEMO_EMAIL)
        print(f"      Created user: {DEMO_EMAIL} / {DEMO_PASSWORD}")
    else:
        print(f"      User {DEMO_EMAIL} already exists (ID: {user['id']})")

    user_id = user["id"]

    # Purge existing demo user scans for idempotency
    print("[2/4] Resetting previous demo scans...")
    with get_connection() as conn:
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.commit()

    print("[3/4] Generating 30+ days of realistic security assessments...")
    now = datetime.now(timezone.utc)
    check_map = {c["id"]: c for c in CHECK_REGISTRY}

    scan_counter = 100
    total_created = 0

    # Generate scans across 35 days, 1 to 3 scans per day
    for days_ago in range(35, -1, -1):
        scan_date = now - timedelta(days=days_ago, hours=random.randint(1, 18), minutes=random.randint(0, 59))
        
        # Decide if scans occur on this day (simulate realistic activity cadence)
        daily_scan_count = random.choices([0, 1, 2, 3], weights=[15, 45, 30, 10])[0]
        if days_ago == 0 and daily_scan_count == 0:
            daily_scan_count = 2 # Always have activity today

        for _ in range(daily_scan_count):
            scan_counter += 1
            scan_id = f"CR-DEMO{scan_counter}"
            target_profile = random.choice(TARGETS)
            target_url = target_profile["url"]
            
            # Show posture improvement over time
            if days_ago < 12:
                failing_ids = target_profile["improved_failing"]
            else:
                failing_ids = target_profile["base_failing"]

            findings = []
            for fid in failing_ids:
                if fid in check_map:
                    cm = check_map[fid]
                    findings.append({
                        "id": fid,
                        "finding_code": fid,
                        "name": cm["name"],
                        "category": cm["category"],
                        "severity": cm["severity"],
                        "confidence": "High",
                        "affected_component": "HTTP Response Headers",
                        "cwe": cm["cwe"],
                        "owasp": cm["owasp"],
                        "evidence": f"Header misconfiguration observed during passive evaluation for {target_profile['domain']}.",
                        "description": cm["why_it_matters"],
                        "recommendation": cm["how_evaluated"],
                    })

            finding_summary = {
                "High": sum(1 for f in findings if f["severity"] == "High"),
                "Medium": sum(1 for f in findings if f["severity"] == "Medium"),
                "Low": sum(1 for f in findings if f["severity"] == "Low"),
                "Info": sum(1 for f in findings if f["severity"] in ("Info", "Informational")),
                "Total": len(findings),
            }

            iso_timestamp = scan_date.strftime("%Y-%m-%d %H:%M:%S")
            human_timestamp = scan_date.strftime("%d %b %Y, %I:%M:%S %p UTC")

            assessment_data = {
                "target": target_url,
                "recon": {
                    "domain": target_profile["domain"],
                    "ip_address": f"198.51.100.{random.randint(10, 200)}",
                    "reachable": True,
                    "status_code": 200,
                    "final_url": target_url,
                    "https_enabled": True if "CR-001" not in failing_ids else False,
                    "response_time": round(random.uniform(22.5, 140.0), 2),
                    "page_title": f"{target_profile['domain']} - Operational Service",
                    "server": "nginx/1.24.0",
                    "content_type": "text/html; charset=UTF-8",
                    "redirect_count": 0,
                    "headers": {},
                    "set_cookies": [],
                },
                "findings": findings,
                "finding_summary": finding_summary,
                "metadata": {
                    "scan_id": scan_id,
                    "started_at": human_timestamp,
                    "duration_ms": random.randint(95, 340),
                    "checks_performed": 18,
                    "recon_status": "Completed",
                    "analysis_status": "Completed",
                },
            }

            db_id = save_assessment(assessment_data, user_id=user_id)
            
            # Backdate created_at in database
            with get_connection() as conn:
                conn.execute(
                    "UPDATE scans SET created_at = ? WHERE id = ?",
                    (iso_timestamp, db_id)
                )
                conn.commit()

            total_created += 1

    print(f"[4/4] Seed complete! Created {total_created} historical scans for {DEMO_EMAIL}.")
    print("\nDEMO CREDENTIALS:")
    print(f"   Email:    {DEMO_EMAIL}")
    print(f"   Password: {DEMO_PASSWORD}")
    print("   Targets:  app.example.com, api.secure-gateway.io, portal.internal-corp.dev\n")
    return total_created


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed demo assessment telemetry for CyberRecon.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete all scans belonging to demo@cyberrecon.local only, leaving other accounts untouched."
    )
    args = parser.parse_args()
    seed_demo_data(reset_only=args.reset)
