"""
Phase 3 Verification Script:
- Full browser verification of all Phase 3 pages across Desktop (1440x900), Tablet (1024x768), and Mobile (390x844) in Dark and Light themes.
- Captures /new (idle, validation, running), /assessments/<id> (canonical report), /history (table, timeline, compare launcher), /compare (delta & matrix), /targets, /settings, and 404 error page.
- Records interactive video of end-to-end user journey.
- Audits console errors across all viewports and interactions.
"""

import os
import sys
import time
import shutil
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
    get_scan_history,
    save_assessment,
)
from scripts.seed_demo import seed_demo_data, DEMO_EMAIL, DEMO_PASSWORD

OUTPUT_DIR = PROJECT_ROOT / "audit_screenshots" / "after"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
VIDEO_DIR = OUTPUT_DIR / "recordings"
VIDEO_DIR.mkdir(parents=True, exist_ok=True)

ARTIFACT_MEDIA_DIR = Path("C:/Users/sujal/.gemini/antigravity/brain/71fa947f-48b8-4e67-bbb9-1ef88520f8b9/media")
ARTIFACT_MEDIA_DIR.mkdir(parents=True, exist_ok=True)

PORT = 5062
BASE_URL = f"http://127.0.0.1:{PORT}"


def setup_data():
    initialize_database()
    # Seed demo user
    seed_demo_data()
    demo_user = get_user_by_email(DEMO_EMAIL)
    scans = get_scan_history(demo_user["id"], limit=10)
    canonical_scan_id = scans[0]["scan_id"] if scans else "CR-DEMO-01"
    print(f"[SETUP] Demo user ready ({DEMO_EMAIL}). Canonical scan for review: {canonical_scan_id}")
    return canonical_scan_id


def run_server():
    app = create_app({"TESTING": True, "CSRF_PROTECTION_ENABLED": False})
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    server.serve_forever()


def copy_to_artifacts(src_path, dst_filename):
    dst_path = ARTIFACT_MEDIA_DIR / dst_filename
    shutil.copy2(src_path, dst_path)
    return dst_path


def run_phase3_verification():
    canonical_scan_id = setup_data()

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

        # Pre-authenticate demo auditor and save state for fast reuse
        auth_context = browser.new_context()
        auth_page = auth_context.new_page()
        auth_page.goto(f"{BASE_URL}/login")
        auth_page.fill("input[name='email']", DEMO_EMAIL)
        auth_page.fill("input[name='password']", DEMO_PASSWORD)
        auth_page.click("button[type='submit']")
        auth_page.wait_for_load_state("networkidle")
        storage_state = auth_context.storage_state()
        auth_context.close()
        print("[AUTH] Demo auditor session state saved for matrix captures.")

        # ---------------------------------------------------------
        # 1. SCREENSHOT MATRIX FOR ALL PHASE 3 PAGES
        # ---------------------------------------------------------
        pages_to_capture = [
            ("new_idle", f"{BASE_URL}/new"),
            ("report_canonical", f"{BASE_URL}/assessments/{canonical_scan_id}"),
            ("history_table", f"{BASE_URL}/history"),
            ("compare_view", f"{BASE_URL}/compare"),
            ("targets_directory", f"{BASE_URL}/targets"),
            ("settings_view", f"{BASE_URL}/settings"),
            ("error_404", f"{BASE_URL}/non-existent-route-for-testing"),
        ]

        print("\n=======================================================")
        print("STAGE 1: Capturing Phase 3 Viewport & Theme Matrix")
        print("=======================================================")

        for page_name, url in pages_to_capture:
            print(f"\n--- Page: {page_name} ({url}) ---")
            for vp_name, width, height in viewports:
                for theme in themes:
                    ctx_kwargs = {
                        "viewport": {"width": width, "height": height},
                        "color_scheme": theme,
                    }
                    if "404" not in page_name:
                        ctx_kwargs["storage_state"] = storage_state

                    context = browser.new_context(**ctx_kwargs)
                    page = context.new_page()

                    page.on("console", lambda msg: console_errors.append(f"[{page_name} {vp_name} {theme}] {msg.text}") if msg.type == "error" else None)
                    page.on("pageerror", lambda exc: console_errors.append(f"[{page_name} {vp_name} {theme}] {exc}"))

                    page.goto(url)
                    page.wait_for_load_state("networkidle")

                    # Apply theme
                    page.evaluate(f"""() => {{
                        document.documentElement.setAttribute('data-theme', '{theme}');
                        localStorage.setItem('cyberrecon-theme', '{theme}');
                    }}""")
                    time.sleep(0.2)

                    # Custom interactions per page if needed
                    if page_name == "history_table" and width == 1440:
                        checkboxes = page.locator(".scan-checkbox")
                        if checkboxes.count() >= 2:
                            checkboxes.nth(0).check()
                            checkboxes.nth(1).check()
                            time.sleep(0.2)

                    filename = f"after_{page_name}_{vp_name}_{theme}.png"
                    filepath = OUTPUT_DIR / filename
                    page.screenshot(path=str(filepath), full_page=True)
                    copy_to_artifacts(filepath, filename)
                    print(f"  [SAVED] {filename} ({width}x{height}, {theme})")

                    context.close()

        # ---------------------------------------------------------
        # 2. CAPTURE SPECIAL STATES: /new validation pulse & running cockpit
        # ---------------------------------------------------------
        print("\n=======================================================")
        print("STAGE 2: Capturing /new Validation & Running Cockpit")
        print("=======================================================")
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark", storage_state=storage_state)
        page = context.new_page()

        page.goto(f"{BASE_URL}/new")
        page.wait_for_load_state("networkidle")

        # Fill valid public target without checking authorization, try to launch
        page.fill("#target", "https://example.com")
        page.keyboard.press("Control+Enter")
        time.sleep(0.6)

        # Screenshot validation highlight
        val_filename = "after_new_validation_highlight_1440_dark.png"
        val_path = OUTPUT_DIR / val_filename
        page.screenshot(path=str(val_path), full_page=True)
        copy_to_artifacts(val_path, val_filename)
        print(f"  [SAVED] {val_filename}")

        # Check authorization and trigger launch
        page.check("#auth-consent-cb")
        time.sleep(0.2)
        page.click("#start-assessment-btn")
        time.sleep(1.2)  # In mid-flight streaming log

        cockpit_filename = "after_new_running_cockpit_1440_dark.png"
        cockpit_path = OUTPUT_DIR / cockpit_filename
        page.screenshot(path=str(cockpit_path), full_page=True)
        copy_to_artifacts(cockpit_path, cockpit_filename)
        print(f"  [SAVED] {cockpit_filename}")

        context.close()

        # ---------------------------------------------------------
        # 3. INTERACTIVE VIDEO RECORDING OF END-TO-END USER JOURNEY
        # ---------------------------------------------------------
        print("\n=======================================================")
        print("STAGE 3: Recording End-to-End User Journey Video")
        print("=======================================================")
        video_context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            color_scheme="dark",
            record_video_dir=str(VIDEO_DIR),
            record_video_size={"width": 1440, "height": 900},
        )
        page = video_context.new_page()

        page.on("console", lambda msg: console_errors.append(f"[video] {msg.text}") if msg.type == "error" else None)
        page.on("pageerror", lambda exc: console_errors.append(f"[video] {exc}"))

        # Step 1: Landing page
        page.goto(f"{BASE_URL}/")
        page.wait_for_load_state("networkidle")
        time.sleep(1.0)
        page.mouse.wheel(0, 450)
        time.sleep(0.8)

        # Step 2: Login as demo auditor
        page.goto(f"{BASE_URL}/login")
        page.fill("input[name='email']", DEMO_EMAIL)
        page.fill("input[name='password']", DEMO_PASSWORD)
        page.click("button[type='submit']")
        page.wait_for_load_state("networkidle")
        time.sleep(1.0)

        # Step 3: Command Center Dashboard
        page.goto(f"{BASE_URL}/dashboard")
        page.wait_for_load_state("networkidle")
        time.sleep(1.2)

        # Step 4: Navigate to /new assessment
        page.click("a[href='/new']")
        page.wait_for_load_state("networkidle")
        time.sleep(1.0)

        # Fill target, switch profile to Full Baseline
        page.fill("#target", "https://api.acme-corp.com")
        time.sleep(0.5)
        page.click("#profile-card-baseline")
        time.sleep(0.6)

        # Try launching without authorization (triggers highlight)
        page.keyboard.press("Control+Enter")
        time.sleep(1.0)

        # Confirm authorization and launch
        page.check("#auth-consent-cb")
        time.sleep(0.4)
        page.click("#start-assessment-btn")
        time.sleep(2.5)  # Streaming log execution

        # Step 5: Canonical Assessment Report
        page.goto(f"{BASE_URL}/assessments/{canonical_scan_id}")
        page.wait_for_load_state("networkidle")
        time.sleep(1.5)

        # Switch tabs: Passed Checks -> Raw Evidence -> Findings
        page.click("button[data-tab='tab-passed']")
        time.sleep(1.0)
        page.click("button[data-tab='tab-raw']")
        time.sleep(1.0)
        page.click("button[data-tab='tab-findings']")
        time.sleep(0.8)

        # Switch remediation tabs: Apache -> Express -> Nginx
        apache_btn = page.locator(".rem-tab:has-text('Apache')").first
        if apache_btn.count():
            apache_btn.click()
            time.sleep(0.6)
        express_btn = page.locator(".rem-tab:has-text('Express.js')").first
        if express_btn.count():
            express_btn.click()
            time.sleep(0.6)
        nginx_btn = page.locator(".rem-tab:has-text('Nginx')").first
        if nginx_btn.count():
            nginx_btn.click()
            time.sleep(0.6)

        # Step 6: Monitored Targets Directory
        page.click("a[href='/targets']")
        page.wait_for_load_state("networkidle")
        time.sleep(1.5)

        # Step 7: Compare Assessments
        page.click("a[href*='/compare']")
        page.wait_for_load_state("networkidle")
        time.sleep(1.5)
        page.mouse.wheel(0, 350)
        time.sleep(1.0)

        # Step 8: Audit History & Multi-Select Compare Launcher
        page.click("a[href='/history']")
        page.wait_for_load_state("networkidle")
        time.sleep(1.0)
        cbs = page.locator(".scan-checkbox")
        if cbs.count() >= 2:
            cbs.nth(0).check()
            time.sleep(0.4)
            cbs.nth(1).check()
            time.sleep(1.0)

        # Switch to timeline view
        page.click("#view-toggle-timeline")
        time.sleep(1.2)
        page.click("#view-toggle-table")
        time.sleep(0.8)

        # Step 9: Platform Settings
        page.click("a[href='/settings']")
        page.wait_for_load_state("networkidle")
        time.sleep(1.0)
        page.click("button[data-tab='tab-appearance']")
        time.sleep(0.8)
        page.click("button[data-tab='tab-data']")
        time.sleep(0.8)

        # Step 10: Trigger Global Command Palette (Ctrl+K)
        page.keyboard.press("Control+k")
        time.sleep(1.2)
        page.keyboard.press("Escape")
        time.sleep(0.5)

        # Finish video
        video_context.close()
        browser.close()

        # Find saved video file and copy
        saved_videos = list(VIDEO_DIR.glob("*.webm"))
        if saved_videos:
            latest_video = max(saved_videos, key=lambda f: f.stat().st_mtime)
            target_vid = VIDEO_DIR / "phase3_user_journey.webm"
            if latest_video != target_vid:
                shutil.copy2(latest_video, target_vid)
            copy_to_artifacts(target_vid, "phase3_user_journey.webm")
            print(f"\n[VIDEO SAVED] {target_vid.name} -> Copied to artifact media")

    print("\n=======================================================")
    print("STAGE 4: Browser Console Error Audit")
    print("=======================================================")
    real_errors = [e for e in console_errors if "favicon" not in e.lower() and "viewtransition" not in e.lower()]
    print(f"Total Console Errors Caught: {len(real_errors)}")
    for err in real_errors:
        print(f"  [ERROR] {err}")

    if len(real_errors) == 0:
        print("\n[VERIFICATION RESULT] 0 CONSOLE ERRORS ACROSS ALL PAGES & VIEWPORTS. TARGET ACHIEVED.")


if __name__ == "__main__":
    run_phase3_verification()
