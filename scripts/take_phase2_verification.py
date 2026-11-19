import os
import sys
import time
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

import werkzeug.serving
from playwright.sync_api import sync_playwright

from werkzeug.security import generate_password_hash
from cyberrecon.app import create_app
from cyberrecon.storage import (
    get_connection,
    initialize_database,
    create_user,
    get_user_by_email,
    save_assessment,
)
from scripts.seed_demo import seed_demo_data, DEMO_EMAIL, DEMO_PASSWORD

OUTPUT_DIR = PROJECT_ROOT / "audit_screenshots" / "after"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
VIDEO_DIR = OUTPUT_DIR / "recordings"
VIDEO_DIR.mkdir(parents=True, exist_ok=True)

PORT = 5058
BASE_URL = f"http://127.0.0.1:{PORT}"

def setup_test_users():
    initialize_database()
    # 1. Seeded user (50+ scans across 3 targets)
    seed_demo_data()

    # 2. 1-scan low-data user
    low_email = "lowdata@cyberrecon.local"
    low_user = get_user_by_email(low_email)
    if not low_user:
        create_user("low_auditor", low_email, generate_password_hash("LowData123!"))
        low_user = get_user_by_email(low_email)
    
    with get_connection() as conn:
        conn.execute("DELETE FROM scans WHERE user_id = ?", (low_user["id"],))
        conn.commit()

    low_scan = {
        "target": "https://single-target.io",
        "recon": {
            "domain": "single-target.io",
            "ip_address": "198.51.100.22",
            "reachable": True,
            "status_code": 200,
            "final_url": "https://single-target.io",
            "https_enabled": True,
            "response_time": 45.0,
            "page_title": "Single Target App",
            "server": "nginx",
            "content_type": "text/html",
            "redirect_count": 0,
            "headers": {},
            "set_cookies": [],
        },
        "findings": [
            {
                "id": "CR-003",
                "finding_code": "CR-003",
                "name": "Content Security Policy Missing",
                "category": "Browser Security",
                "severity": "Medium",
                "confidence": "High",
                "affected_component": "HTTP Headers",
                "cwe": "CWE-693",
                "owasp": "OWASP A05",
                "evidence": "Missing CSP",
                "description": "CSP missing",
                "recommendation": "Add CSP",
            }
        ],
        "finding_summary": {"High": 0, "Medium": 1, "Low": 0, "Info": 0, "Total": 1},
        "metadata": {
            "scan_id": "CR-SINGLE01",
            "started_at": "18 Nov 2026, 02:00:00 PM UTC",
            "duration_ms": 110,
            "checks_performed": 18,
            "recon_status": "Completed",
            "analysis_status": "Completed",
        },
    }
    save_assessment(low_scan, user_id=low_user["id"])

    # 3. 0-scan empty user
    empty_email = "empty@cyberrecon.local"
    empty_user = get_user_by_email(empty_email)
    if not empty_user:
        create_user("empty_auditor", empty_email, generate_password_hash("EmptyData123!"))
        empty_user = get_user_by_email(empty_email)
    with get_connection() as conn:
        conn.execute("DELETE FROM scans WHERE user_id = ?", (empty_user["id"],))
        conn.commit()

    print("[SETUP] Users ready: demo (52 scans), lowdata (1 scan), empty (0 scans)")

def run_server():
    app = create_app({"TESTING": True, "CSRF_PROTECTION_ENABLED": False})
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    server.serve_forever()

def capture_phase2():
    setup_test_users()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)

    viewports = [
        ("desktop_1440", 1440, 900),
        ("tablet_1024", 1024, 768),
        ("mobile_390", 390, 844),
    ]
    themes = ["dark", "light"]

    console_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        user_scenarios = [
            ("seeded", DEMO_EMAIL, DEMO_PASSWORD),
            ("1scan_lowdata", "lowdata@cyberrecon.local", "LowData123!"),
            ("0scan_empty", "empty@cyberrecon.local", "EmptyData123!"),
        ]

        # 1. State & Viewport Matrices
        for scenario_name, email, pwd in user_scenarios:
            print(f"\n--- Capturing Scenario: {scenario_name} ({email}) ---")
            for vp_name, width, height in viewports:
                for theme in themes:
                    context = browser.new_context(
                        viewport={"width": width, "height": height},
                        color_scheme=theme,
                    )
                    page = context.new_page()

                    page.on("console", lambda msg: console_errors.append(f"[{scenario_name}] {msg.text}") if msg.type == "error" else None)
                    page.on("pageerror", lambda exc: console_errors.append(f"[{scenario_name}] {exc}"))

                    # Log in
                    page.goto(f"{BASE_URL}/login")
                    page.fill("input[name='email']", email)
                    page.fill("input[name='password']", pwd)
                    page.click("button[type='submit']")
                    page.wait_for_load_state("networkidle")

                    # Open dashboard
                    page.goto(f"{BASE_URL}/dashboard")
                    page.wait_for_load_state("networkidle")

                    # Set theme
                    page.evaluate(f"""() => {{
                        document.documentElement.setAttribute('data-theme', '{theme}');
                        localStorage.setItem('cyberrecon-theme', '{theme}');
                    }}""")
                    time.sleep(0.3)

                    filename = f"after_dashboard_{scenario_name}_{vp_name}_{theme}.png"
                    filepath = OUTPUT_DIR / filename
                    page.screenshot(path=str(filepath), full_page=True)
                    print(f"[CAPTURED] {filename} ({width}x{height}, {theme})")

                    context.close()

        # 2. Record Key Interactions on Seeded Dashboard
        print("\n--- Recording Interactive Cross-Filtering & Motions ---")
        video_context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            color_scheme="dark",
            record_video_dir=str(VIDEO_DIR),
            record_video_size={"width": 1440, "height": 900},
        )
        page = video_context.new_page()

        page.on("console", lambda msg: console_errors.append(f"[video] {msg.text}") if msg.type == "error" else None)
        page.on("pageerror", lambda exc: console_errors.append(f"[video] {exc}"))

        # Log in as demo user
        page.goto(f"{BASE_URL}/login")
        page.fill("input[name='email']", DEMO_EMAIL)
        page.fill("input[name='password']", DEMO_PASSWORD)
        page.click("button[type='submit']")
        page.wait_for_load_state("networkidle")

        page.goto(f"{BASE_URL}/dashboard")
        page.wait_for_load_state("networkidle")
        time.sleep(0.8)

        # Hover across SVG area chart dots
        dots = page.locator(".chart-dot")
        dot_count = dots.count()
        if dot_count > 0:
            for idx in range(min(5, dot_count)):
                dots.nth(idx).hover()
                time.sleep(0.35)

        # Click High Severity filter in Donut legend
        high_legend = page.locator(".donut-legend-item").first
        if high_legend.count() > 0:
            high_legend.click()
            page.wait_for_load_state("networkidle")
            time.sleep(0.6)

        # Select target filter
        target_select = page.locator("#dashboard-target-selector")
        if target_select.count() > 0:
            target_select.select_option("https://app.example.com")
            page.wait_for_load_state("networkidle")
            time.sleep(0.6)

        # Switch timeframe filter to 7d
        btn_7d = page.locator(".timeframe-btn:has-text('7d')")
        if btn_7d.count() > 0:
            btn_7d.click()
            page.wait_for_load_state("networkidle")
            time.sleep(0.6)

        # Filter recent table
        search_box = page.locator("#dashboard-table-search")
        if search_box.count() > 0:
            search_box.fill("CR-")
            time.sleep(0.4)

        # Scroll down to view matrix and calendar
        page.evaluate("window.scrollTo({ top: 800, behavior: 'smooth' })")
        time.sleep(0.8)

        video_context.close()
        browser.close()

    print("\n" + "="*50)
    print("PHASE 2 DASHBOARD VERIFICATION SUMMARY:")
    print(f"Total Browser Console Errors: {len(console_errors)}")
    if console_errors:
        for err in console_errors:
            print(f"   -> {err}")
    print("="*50)

if __name__ == "__main__":
    capture_phase2()
