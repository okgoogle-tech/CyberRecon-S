"""
Comprehensive Visual QA & Automated Verification Script for CyberRecon
Verifies:
1. Exact container alignment: Nav left == Main left (+/- 1px) across 1440, 1024, 390
2. Zero horizontal overflow across all viewports
3. No left-edge content clipping (left >= 0)
4. Zero visible doubled text or banned strings
5. Dark and light modes
6. Captures screenshots into artifact media directory
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

def run_qa():
    app = create_app()
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(1.2)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        def login_as(context, user_id=4):
            # Inject session cookie for user_id directly
            # Or use test login route / client session
            # CyberRecon session is signed via its secret_key
            from flask.sessions import SecureCookieSerializer
            # Alternatively, login via form
            page = context.new_page()
            # If user 4 is demo_auditor, let's login via form or test endpoint
            # Let's check user password: demo_auditor was created with a known hash
            # We can also add a quick session helper route in app or test login
            page.close()

        # Create separate contexts for each user state
        # Context 1: Public / Logged Out
        ctx_public = browser.new_context()

        # Context 2: User 4 (Seeded 46 scans)
        ctx_user4 = browser.new_context()

        # Context 3: User 5 (1 scan low data)
        ctx_user5 = browser.new_context()

        # Context 4: User 6 (0 scans empty)
        ctx_user6 = browser.new_context()

        # Let's perform session login for contexts
        for ctx, uid in [(ctx_user4, 4), (ctx_user5, 5), (ctx_user6, 6)]:
            # Use Flask's test client serializer to generate a valid session cookie
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
                    # Get cookie from test client
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
                page = ctx_public.new_page(viewport={"width": w, "height": h})
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

                # Screenshot
                shot_path = MEDIA_DIR / f"landing_{vp_name}_{theme}.png"
                page.screenshot(path=str(shot_path), full_page=(vp_name == "desktop_1440"))
                print(f"  [PASS] Landing {vp_name} {theme} -> {shot_path.name}")
                page.close()

        # -------------------------------------------------------------
        # 2. DASHBOARD (User 4 - Seeded Demo Data)
        # -------------------------------------------------------------
        for vp_name, w, h in viewports:
            for theme in ["dark", "light"]:
                page = ctx_user4.new_page(viewport={"width": w, "height": h})
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
                print(f"  [PASS] Dashboard Seeded {vp_name} {theme} -> {shot_path.name}")
                page.close()

        # -------------------------------------------------------------
        # 3. DASHBOARD (User 5 - 1-Scan Low Data State)
        # -------------------------------------------------------------
        page = ctx_user5.new_page(viewport={"width": 1440, "height": 900})
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
        page = ctx_user6.new_page(viewport={"width": 1440, "height": 900})
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
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{BASE_URL}/new")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "new_assessment_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] New Assessment 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 6. ABOUT PAGE (/about - 18 checks catalog)
        # -------------------------------------------------------------
        for theme in ["dark", "light"]:
            page = ctx_public.new_page(viewport={"width": 1440, "height": 900})
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
            print(f"  [PASS] About 1440 {theme} -> {shot_path.name}")
            page.close()

        # -------------------------------------------------------------
        # 7. REPORT PAGE FOR HTTP TARGET (/assessments/CR-HTTP001)
        # -------------------------------------------------------------
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{BASE_URL}/assessments/CR-HTTP001")
        page.wait_for_load_state("networkidle")
        nav = page.locator(".navbar .nav-container").bounding_box()
        main = page.locator("main.container").bounding_box()
        assert abs(nav["x"] - main["x"]) <= 1.0
        shot_path = MEDIA_DIR / "report_http_target_1440_dark.png"
        page.screenshot(path=str(shot_path), full_page=True)
        print(f"  [PASS] Report HTTP Target 1440 dark -> {shot_path.name}")
        page.close()

        # -------------------------------------------------------------
        # 8. COMPARE PAGE (/compare)
        # -------------------------------------------------------------
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
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
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
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
        # 10. SETTINGS PAGE (/settings)
        # -------------------------------------------------------------
        page = ctx_user4.new_page(viewport={"width": 1440, "height": 900})
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
        # 11. ERROR 404 PAGE
        # -------------------------------------------------------------
        page = ctx_public.new_page(viewport={"width": 1440, "height": 900})
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

if __name__ == "__main__":
    run_qa()
