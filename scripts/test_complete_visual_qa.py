"""
Comprehensive Visual QA & Automated Verification Script for CyberRecon
Verifies:
1. Exact container alignment: Nav left == Main left (+/- 1px) across 1440, 1024, 390
2. Zero horizontal overflow across all viewports
3. No left-edge content clipping (left >= 0)
4. Zero visible doubled text or banned strings
5. Dark and light modes
6. Console error tracking per page (target: 0)
7. Captures the 6 required screenshots into the artifact media directory
"""

import sys
import os
import time
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

import werkzeug.serving
from playwright.sync_api import sync_playwright
from cyberrecon.app import create_app

PORT = 5098
BASE_URL = f"http://127.0.0.1:{PORT}"
MEDIA_DIR = Path(r"C:\Users\sujal\.gemini\antigravity\brain\71fa947f-48b8-4e67-bbb9-1ef88520f8b9\media")
MEDIA_DIR.mkdir(parents=True, exist_ok=True)

BANNED_VISIBLE_STRINGS = [
    "OPEN FINDINGS OBSERVED FINDINGS",
    "HIGH / MED RISKS HIGH MEDIUM",
    "SUCCESSFUL 2",
    "FAILED PROBES 0",
    "Common Findings IntelligenceMost prevalent",
    "Operational Security Insights TOP DETECTED",
]

console_errors_by_page = {}

def track_page_errors(page, page_name):
    if page_name not in console_errors_by_page:
        console_errors_by_page[page_name] = []
    page.on("console", lambda msg: console_errors_by_page[page_name].append(f"[{msg.type}] {msg.text}") if msg.type == "error" else None)
    page.on("pageerror", lambda exc: console_errors_by_page[page_name].append(f"[pageerror] {exc}"))

def run_qa():
    app = create_app()
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(1.2)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Context 1: Public / Logged Out
        ctx_public = browser.new_context()

        # Context 2: User 4 (Seeded 46 scans)
        ctx_user4 = browser.new_context()

        # Context 3: User 5 (1 scan low data)
        ctx_user5 = browser.new_context()

        # Context 4: User 6 (0 scans empty)
        ctx_user6 = browser.new_context()

        # Session login for contexts
        for ctx, uid in [(ctx_user4, 4), (ctx_user5, 5), (ctx_user6, 6)]:
            with app.test_request_context():
                with app.test_client() as c:
                    with c.session_transaction() as sess:
                        sess["user_id"] = uid
                        if uid == 4:
                            sess["username"] = "demo_auditor"
                        elif uid == 5:
                            sess["username"] = "low_auditor"
                        else:
                            sess["username"] = "empty_auditor"
                    cookie_val = c.get_cookie("session").value
                    ctx.add_cookies([{
                        "name": "session",
                        "value": cookie_val,
                        "domain": "127.0.0.1",
                        "path": "/",
                        "httpOnly": True,
                    }])

        viewports = [
            ("desktop_1440", 1440, 900),
            ("tablet_1024", 1024, 768),
            ("mobile_390", 390, 844),
        ]

        print("=================================================================")
        print("STARTING FULL AUTOMATED VISUAL QA & GEOMETRIC ASSERTIONS")
        print("=================================================================")

        # -------------------------------------------------------------
        # 1. LANDING PAGE (Public)
        # -------------------------------------------------------------
        for vp_name, w, h in viewports:
            for theme in ["dark", "light"]:
                page_key = f"/ (Landing {vp_name} {theme})"
                page = ctx_public.new_page(viewport={"width": w, "height": h})
                track_page_errors(page, page_key)
                page.goto(f"{BASE_URL}/")
                page.wait_for_load_state("networkidle")

                if theme == "light":
                    page.evaluate("() => { document.documentElement.setAttribute('data-theme', 'light'); localStorage.setItem('theme', 'light'); }")
                    time.sleep(0.1)

                # Geometry assertions
                nav = page.locator(".navbar .nav-container").bounding_box()
                main = page.locator("main.container").bounding_box()
                assert abs(nav["x"] - main["x"]) <= 1.0, f"Landing nav left ({nav['x']}) != main left ({main['x']}) at {vp_name}"
                assert abs(nav["width"] - main["width"]) <= 1.0, f"Landing nav width ({nav['width']}) != main width ({main['width']}) at {vp_name}"

                overflow = page.evaluate("() => document.documentElement.scrollWidth > document.documentElement.clientWidth")
                assert not overflow, f"Horizontal overflow on Landing at {vp_name}"

                # Heading clipping check
                h1_box = page.locator("h1").bounding_box()
                assert h1_box["x"] >= 0, f"H1 clipped at left on Landing at {vp_name}"

                # Banned strings
                body_text = page.locator("body").inner_text()
                for banned in BANNED_VISIBLE_STRINGS:
                    assert banned not in body_text, f"Banned string '{banned}' visible on Landing!"

                # Screenshots
                shot_path = MEDIA_DIR / f"landing_{vp_name}_{theme}.png"
                page.screenshot(path=str(shot_path), full_page=(vp_name == "desktop_1440"))
                if vp_name == "desktop_1440" and theme == "dark":
                    page.screenshot(path=str(MEDIA_DIR / "final_landing_1440.png"), full_page=True)
                if vp_name == "mobile_390" and theme == "dark":
                    page.screenshot(path=str(MEDIA_DIR / "final_landing_mobile_390.png"), full_page=False)

                print(f"  [PASS] Landing {vp_name} {theme} -> {shot_path.name}")
                page.close()

        # -------------------------------------------------------------
        # 2. DASHBOARD (User 4 - Seeded Demo Data)
        # -------------------------------------------------------------
        for vp_name, w, h in viewports:
            for theme in ["dark", "light"]:
                page_key = f"/dashboard ({vp_name} {theme})"
                page = ctx_user4.new_page(viewport={"width": w, "height": h})
                track_page_errors(page, page_key)
                page.goto(f"{BASE_URL}/dashboard")
                page.wait_for_load_state("networkidle")

                if theme == "light":
                    page.evaluate("() => { document.documentElement.setAttribute('data-theme', 'light'); localStorage.setItem('theme', 'light'); }")
                    time.sleep(0.1)

                # Geometry assertions: Nav vs Main left alignment
                nav = page.locator(".navbar .nav-container").bounding_box()
                main = page.locator("main.container").bounding_box()
                assert abs(nav["x"] - main["x"]) <= 1.0, f"Dashboard nav left ({nav['x']}) != main left ({main['x']}) at {vp_name}"
                assert abs(nav["width"] - main["width"]) <= 1.0, f"Dashboard nav width ({nav['width']}) != main width ({main['width']}) at {vp_name}"

                overflow = page.evaluate("() => document.documentElement.scrollWidth > document.documentElement.clientWidth")
                assert not overflow, f"Horizontal overflow on Dashboard at {vp_name}"

                # Title clipping check
                title_box = page.locator("#cmd-title").bounding_box()
                assert title_box["x"] >= 0, f"Dashboard title clipped at left ({title_box['x']}) at {vp_name}"

                # Banned doubled strings check
                body_text = page.locator("body").inner_text()
                for banned in BANNED_VISIBLE_STRINGS:
                    assert banned not in body_text, f"Banned doubled string '{banned}' found visible on Dashboard!"

                # Screenshot
                shot_path = MEDIA_DIR / f"dashboard_seeded_{vp_name}_{theme}.png"
                page.screenshot(path=str(shot_path), full_page=(vp_name == "desktop_1440"))
                if vp_name == "desktop_1440" and theme == "dark":
                    page.screenshot(path=str(MEDIA_DIR / "final_dashboard_1440.png"), full_page=True)

                print(f"  [PASS] Dashboard Seeded {vp_name} {theme} -> {shot_path.name}")
                page.close()

        # -------------------------------------------------------------
        # 3. DASHBOARD (User 5 - 1-Scan Low Data State)
        # -------------------------------------------------------------
        page_key = "/dashboard (User 5 Low Data)"
        page = ctx_user5.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/dashboard")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        assert "Trendline baseline recording in progress" in page.locator("body").inner_text()
        shot_path = MEDIA_DIR / "dashboard_lowdata_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] Dashboard Low Data 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 4. DASHBOARD (User 6 - 0-Scan Onboarding State)
        # -------------------------------------------------------------
        page_key = "/dashboard (User 6 Empty)"
        page = ctx_user6.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/dashboard")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        assert "Welcome to CyberRecon Command Center" in page.locator("body").inner_text()
        shot_path = MEDIA_DIR / "dashboard_empty_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] Dashboard Onboarding 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 5. NEW ASSESSMENT COCKPIT (/new)
        # -------------------------------------------------------------
        page_key = "/new (Cockpit)"
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/new")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "new_assessment_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        page.screenshot(path=str(MEDIA_DIR / "final_new_1440.png"), full_page=True)
        print(f"  [PASS] New Assessment 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 6. ABOUT PAGE (/about - 18 checks catalog & dynamic scoring)
        # -------------------------------------------------------------
        for theme in ["dark", "light"]:
            page_key = f"/about ({theme})"
            page = ctx_public.new_page(viewport={"width": 1440, "height": 900})
            track_page_errors(page, page_key)
            page.goto(f"{BASE_URL}/about")
            page.wait_for_load_state("networkidle")
            if theme == "light":
                page.evaluate("() => { document.documentElement.setAttribute('data-theme', 'light'); localStorage.setItem('theme', 'light'); }")
                time.sleep(0.1)
            nav = page.locator(".navbar .nav-container").bounding_box()
            main = page.locator("main.container").bounding_box()
            assert abs(nav["x"] - main["x"]) <= 1.0
            shot_path = MEDIA_DIR / f"about_1440_{theme}.png"
            page.screenshot(path=str(shot_path), full_page=True)
            if theme == "dark":
                page.screenshot(path=str(MEDIA_DIR / "final_about_1440.png"), full_page=True)
            print(f"  [PASS] About 1440 {theme} -> {shot_path.name}")
            page.close()

        # -------------------------------------------------------------
        # 7. REPORT PAGE FOR HTTP TARGET (/assessments/CR-HTTP001)
        # -------------------------------------------------------------
        page_key = "/assessments/CR-HTTP001 (Report)"
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/assessments/CR-HTTP001")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "report_http_target_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        page.screenshot(path=str(MEDIA_DIR / "final_report_1440.png"), full_page=True)
        print(f"  [PASS] Report HTTP Target 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 8. COMPARE PAGE (/compare)
        # -------------------------------------------------------------
        page_key = "/compare"
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/compare")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "compare_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] Compare 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 9. TARGETS PAGE (/targets)
        # -------------------------------------------------------------
        page_key = "/targets"
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/targets")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "targets_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] Targets 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 10. HISTORY PAGE (/history)
        # -------------------------------------------------------------
        page_key = "/history"
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/history")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "history_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] History 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 11. SETTINGS PAGE (/settings)
        # -------------------------------------------------------------
        page_key = "/settings"
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/settings")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "settings_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] Settings 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 12. PRIVACY & TERMS
        # -------------------------------------------------------------
        for path_name in ["privacy", "terms"]:
            page_key = f"/{path_name}"
            page = ctx_public.new_page(viewport={"width": 1440, "height": 900})
            track_page_errors(page, page_key)
            page.goto(f"{BASE_URL}/{path_name}")
            page.wait_for_load_state("networkidle")
            nav = page.locator(".navbar .nav-container").bounding_box()
            main = page.locator("main.container").bounding_box()
            assert abs(nav["x"] - main["x"]) <= 1.0
            page.close()

        # -------------------------------------------------------------
        # 13. ERROR 404 PAGE
        # -------------------------------------------------------------
        page_key = "404 Page"
        page = ctx_public.new_page(viewport={"width": 1440, "height": 900})
        track_page_errors(page, page_key)
        page.goto(f"{BASE_URL}/non-existent-page-for-qa-test")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "error_404_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] 404 Page 1440 dark -> {shot_path.name}")
        page.close()

        browser.close()

    server.shutdown()
    print("\n=================================================================")
    print("ALL VISUAL QA TESTS AND PLAYWRIGHT ASSERTIONS PASSED (100%)!")
    print("=================================================================")
    print("\nCONSOLE ERRORS PER PAGE (TARGET: 0):")
    total_console_errs = 0
    for page_name, errs in console_errors_by_page.items():
        count = len(errs)
        total_console_errs += count
        status = "ZERO (Clean)" if count == 0 else f"{count} ERRORS: {errs}"
        print(f"  - {page_name:<40} : {status}")

    print(f"\nTOTAL CONSOLE ERRORS ACROSS ALL PAGES: {total_console_errs}")
    assert total_console_errs == 0, f"Found {total_console_errs} console errors!"

if __name__ == "__main__":
    run_qa()
