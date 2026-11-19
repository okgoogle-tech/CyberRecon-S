"""
Automated Visual QA & Playwright Matrix for CyberRecon
- Starts Flask server as a subprocess with readiness poll, kills in finally
- Uses domcontentloaded + explicit selector wait (never networkidle)
- Enforces 8s default timeout & 15s nav timeout
- Compact matrix: key pages at 1440 dark, 390 mobile, 1024/1440 light
- Captures the 4 required screenshots:
  1. landing shot at scroll 0 (tilted)
  2. shot when centered (flat)
  3. report page showing Download button
  4. report page with Download dropdown open
- Records console errors per page (target: 0)
"""

import sys
import os
import time
import subprocess
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from playwright.sync_api import sync_playwright
from cyberrecon.app import create_app

PORT = 5099
BASE_URL = f"http://127.0.0.1:{PORT}"
SERVER_SCRIPT = PROJECT_ROOT / "scripts" / "run_server.py"
MEDIA_DIR = Path(r"C:\Users\sujal\.gemini\antigravity\brain\71fa947f-48b8-4e67-bbb9-1ef88520f8b9\media")
MEDIA_DIR.mkdir(parents=True, exist_ok=True)

BANNED_VISIBLE_STRINGS = [
    "OPEN FINDINGS OBSERVED FINDINGS",
    "HIGH / MED RISKS HIGH MEDIUM",
    "SUCCESSFUL 2",
    "FAILED PROBES 0",
    "Common Findings IntelligenceMost prevalent",
    "Operational Security Insights TOP DETECTED",
    "Simulated Output",
]

console_errors_by_page = {}

def track_page_errors(page, page_name):
    if page_name not in console_errors_by_page:
        console_errors_by_page[page_name] = []
    def on_console(msg):
        if msg.type == "error":
            # Ignore expected 404 HTTP status log on deliberate 404 error page test
            if "status of 404" in msg.text and "404" in page_name:
                return
            console_errors_by_page[page_name].append(f"[{msg.type}] {msg.text}")
    page.on("console", on_console)
    page.on("pageerror", lambda exc: console_errors_by_page[page_name].append(f"[pageerror] {exc}"))

def run_qa():
    print("=================================================================")
    print("STARTING ROBUST VISUAL QA MATRIX & SCREENSHOT CAPTURE")
    print(f"Server script: {SERVER_SCRIPT} on port {PORT}")
    print("=================================================================")

    # 1. Start Flask subprocess with readiness poll
    proc = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT), str(PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    ready = False
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{BASE_URL}/") as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.1)

    if not ready:
        proc.kill()
        raise RuntimeError("Flask server subprocess failed to start on port " + str(PORT))

    print(f"[OK] Flask server subprocess ready at {BASE_URL}")

    try:
        app = create_app()
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # Public context
            ctx_public = browser.new_context()

            # Authenticated Context: User 4 (demo_auditor - 46 scans)
            ctx_user4 = browser.new_context()
            with app.test_request_context():
                with app.test_client() as c:
                    with c.session_transaction() as sess:
                        sess["user_id"] = 4
                        sess["username"] = "demo_auditor"
                    cookie_val = c.get_cookie("session").value
                    ctx_user4.add_cookies([{
                        "name": "session",
                        "value": cookie_val,
                        "domain": "127.0.0.1",
                        "path": "/",
                        "httpOnly": True,
                    }])

            def check_geometry(page, page_label):
                nav = page.locator(".navbar .nav-container").bounding_box()
                main = page.locator("main.container").bounding_box()
                if nav and main:
                    assert abs(nav["x"] - main["x"]) <= 1.0, f"{page_label} nav left ({nav['x']}) != main left ({main['x']})"
                overflow = page.evaluate("() => document.documentElement.scrollWidth > document.documentElement.clientWidth")
                assert not overflow, f"Horizontal overflow on {page_label}"
                # Check banned strings
                body_text = page.locator("body").inner_text()
                for banned in BANNED_VISIBLE_STRINGS:
                    assert banned not in body_text, f"Banned string '{banned}' found visible on {page_label}!"

            # Helper to create page with viewport
            def create_viewport_page(ctx, w, h):
                pg = ctx.new_page()
                pg.set_viewport_size({"width": w, "height": h})
                pg.set_default_timeout(8000)
                return pg

            # -------------------------------------------------------------
            # A. KEY PAGES AT 1440 DARK
            # -------------------------------------------------------------
            print("\n--- Testing Matrix: Desktop 1440 Dark ---")

            # 1. Landing Page
            p_land = create_viewport_page(ctx_public, 1440, 900)
            track_page_errors(p_land, "/ (Landing 1440 dark)")
            p_land.goto(f"{BASE_URL}/", wait_until="domcontentloaded")
            p_land.wait_for_selector("#product-shot-window")
            check_geometry(p_land, "Landing 1440 dark")

            # Capture Screenshot 1: landing shot at scroll 0 (tilted)
            shot_el = p_land.locator("#product-shot-wrap")
            shot_el.screenshot(path=str(MEDIA_DIR / "landing_shot_scroll_0.png"))
            p_land.screenshot(path=str(MEDIA_DIR / "final_landing_1440.png"), full_page=True)
            print("  [PASS] Landing 1440 dark -> captured landing_shot_scroll_0.png")

            # Scroll shot to center & Capture Screenshot 2: shot when centered (flat)
            p_land.evaluate("""() => {
                document.documentElement.style.scrollBehavior = 'auto';
                const wrap = document.getElementById('product-shot-wrap');
                const rect = wrap.getBoundingClientRect();
                const targetY = window.scrollY + rect.top - (window.innerHeight - rect.height) / 2;
                window.scrollTo(0, targetY);
                window.dispatchEvent(new Event('scroll'));
            }""")
            p_land.wait_for_timeout(300)
            shot_el.screenshot(path=str(MEDIA_DIR / "landing_shot_centered_flat.png"))
            print("  [PASS] Landing Shot Centered -> captured landing_shot_centered_flat.png")
            p_land.close()

            # 2. Dashboard Page (1440 dark)
            p_dash = create_viewport_page(ctx_user4, 1440, 900)
            track_page_errors(p_dash, "/dashboard (1440 dark)")
            p_dash.goto(f"{BASE_URL}/dashboard", wait_until="domcontentloaded")
            p_dash.wait_for_selector("#cmd-title")
            check_geometry(p_dash, "Dashboard 1440 dark")
            p_dash.screenshot(path=str(MEDIA_DIR / "final_dashboard_1440.png"), full_page=True)
            print("  [PASS] Dashboard 1440 dark -> captured final_dashboard_1440.png")
            p_dash.close()

            # 3. New Assessment Cockpit (1440 dark)
            p_new = create_viewport_page(ctx_user4, 1440, 900)
            track_page_errors(p_new, "/new (1440 dark)")
            p_new.goto(f"{BASE_URL}/new", wait_until="domcontentloaded")
            p_new.wait_for_selector("form")
            check_geometry(p_new, "New Assessment 1440 dark")
            p_new.screenshot(path=str(MEDIA_DIR / "final_new_1440.png"), full_page=True)
            print("  [PASS] New Assessment 1440 dark -> captured final_new_1440.png")
            p_new.close()

            # 4. Canonical Report Page (/assessments/CR-HTTP001)
            p_rep = create_viewport_page(ctx_user4, 1440, 900)
            track_page_errors(p_rep, "/assessments/CR-HTTP001 (Report 1440 dark)")
            p_rep.goto(f"{BASE_URL}/assessments/CR-HTTP001", wait_until="domcontentloaded")
            p_rep.wait_for_selector("#download-group")
            check_geometry(p_rep, "Report 1440 dark")

            # Capture Screenshot 3: Report page showing Download split button
            p_rep.screenshot(path=str(MEDIA_DIR / "report_download_button.png"), full_page=True)
            p_rep.screenshot(path=str(MEDIA_DIR / "final_report_1440.png"), full_page=True)
            print("  [PASS] Report 1440 dark -> captured report_download_button.png")

            # Open Download Dropdown & Capture Screenshot 4: Dropdown open
            p_rep.locator("#btn-download-dropdown-toggle").click()
            p_rep.wait_for_timeout(200)
            assert p_rep.locator("#download-dropdown-menu").is_visible(), "Download dropdown menu did not open!"
            p_rep.screenshot(path=str(MEDIA_DIR / "report_download_dropdown_open.png"), full_page=False)
            print("  [PASS] Report Dropdown Open -> captured report_download_dropdown_open.png")
            p_rep.close()

            # 5. History Page (1440 dark)
            p_hist = create_viewport_page(ctx_user4, 1440, 900)
            track_page_errors(p_hist, "/history (1440 dark)")
            p_hist.goto(f"{BASE_URL}/history", wait_until="domcontentloaded")
            p_hist.wait_for_selector(".history-row")
            check_geometry(p_hist, "History 1440 dark")
            assert p_hist.locator(".download-row-btn").count() > 0, "No download row button in history table!"
            print("  [PASS] History 1440 dark (with row download icons)")
            p_hist.close()

            # 6. Compare Page (1440 dark)
            p_comp = create_viewport_page(ctx_user4, 1440, 900)
            track_page_errors(p_comp, "/compare (1440 dark)")
            p_comp.goto(f"{BASE_URL}/compare", wait_until="domcontentloaded")
            p_comp.wait_for_selector("main.container")
            check_geometry(p_comp, "Compare 1440 dark")
            print("  [PASS] Compare 1440 dark")
            p_comp.close()

            # 7. Targets Page (1440 dark)
            p_targ = create_viewport_page(ctx_user4, 1440, 900)
            track_page_errors(p_targ, "/targets (1440 dark)")
            p_targ.goto(f"{BASE_URL}/targets", wait_until="domcontentloaded")
            p_targ.wait_for_selector("main.container")
            check_geometry(p_targ, "Targets 1440 dark")
            print("  [PASS] Targets 1440 dark")
            p_targ.close()

            # 8. Settings Page (1440 dark)
            p_sett = create_viewport_page(ctx_user4, 1440, 900)
            track_page_errors(p_sett, "/settings (1440 dark)")
            p_sett.goto(f"{BASE_URL}/settings", wait_until="domcontentloaded")
            p_sett.wait_for_selector("main.container")
            check_geometry(p_sett, "Settings 1440 dark")
            print("  [PASS] Settings 1440 dark")
            p_sett.close()

            # 9. About Page (1440 dark)
            p_abt = create_viewport_page(ctx_public, 1440, 900)
            track_page_errors(p_abt, "/about (1440 dark)")
            p_abt.goto(f"{BASE_URL}/about", wait_until="domcontentloaded")
            p_abt.wait_for_selector("#scoring")
            check_geometry(p_abt, "About 1440 dark")
            p_abt.screenshot(path=str(MEDIA_DIR / "final_about_1440.png"), full_page=True)
            print("  [PASS] About 1440 dark -> captured final_about_1440.png")
            p_abt.close()

            # 10. 404 Error Page (1440 dark)
            p_404 = create_viewport_page(ctx_public, 1440, 900)
            track_page_errors(p_404, "404 Page (1440 dark)")
            p_404.goto(f"{BASE_URL}/non-existent-page-qa-test", wait_until="domcontentloaded")
            p_404.wait_for_selector("main.container")
            check_geometry(p_404, "404 Page 1440 dark")
            print("  [PASS] 404 Error Page 1440 dark")
            p_404.close()

            # -------------------------------------------------------------
            # B. MOBILE 390PX MATRIX (Landing, Dashboard, New, Report)
            # -------------------------------------------------------------
            print("\n--- Testing Matrix: Mobile 390 Dark ---")
            for path, name, sel, is_auth in [
                ("/", "Landing 390", "#product-shot-window", False),
                ("/dashboard", "Dashboard 390", "#cmd-title", True),
                ("/new", "New 390", "form", True),
                ("/assessments/CR-HTTP001", "Report 390", "#download-group", True),
            ]:
                ctx = ctx_user4 if is_auth else ctx_public
                p_mob = create_viewport_page(ctx, 390, 844)
                track_page_errors(p_mob, f"{path} (Mobile 390)")
                p_mob.goto(f"{BASE_URL}{path}", wait_until="domcontentloaded")
                p_mob.wait_for_selector(sel)
                check_geometry(p_mob, name)
                if path == "/":
                    p_mob.screenshot(path=str(MEDIA_DIR / "final_landing_mobile_390.png"), full_page=False)
                print(f"  [PASS] {name}")
                p_mob.close()

            # -------------------------------------------------------------
            # C. LIGHT THEME MATRIX (Landing & Dashboard at 1440 & 1024)
            # -------------------------------------------------------------
            print("\n--- Testing Matrix: Light Theme (1440 & 1024) ---")
            for vp_w, vp_h, vp_name in [(1440, 900, "1440"), (1024, 768, "1024")]:
                # Landing Light
                p_l = create_viewport_page(ctx_public, vp_w, vp_h)
                track_page_errors(p_l, f"/ (Landing Light {vp_name})")
                p_l.goto(f"{BASE_URL}/", wait_until="domcontentloaded")
                p_l.wait_for_selector("#product-shot-window")
                p_l.evaluate("() => { document.documentElement.setAttribute('data-theme', 'light'); localStorage.setItem('theme', 'light'); }")
                p_l.wait_for_timeout(100)
                check_geometry(p_l, f"Landing Light {vp_name}")
                print(f"  [PASS] Landing Light {vp_name}")
                p_l.close()

                # Dashboard Light
                p_d = create_viewport_page(ctx_user4, vp_w, vp_h)
                track_page_errors(p_d, f"/dashboard (Light {vp_name})")
                p_d.goto(f"{BASE_URL}/dashboard", wait_until="domcontentloaded")
                p_d.wait_for_selector("#cmd-title")
                p_d.evaluate("() => { document.documentElement.setAttribute('data-theme', 'light'); localStorage.setItem('theme', 'light'); }")
                p_d.wait_for_timeout(100)
                check_geometry(p_d, f"Dashboard Light {vp_name}")
                print(f"  [PASS] Dashboard Light {vp_name}")
                p_d.close()

            browser.close()

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        print("\n[OK] Flask server subprocess terminated cleanly.")

    print("\n=================================================================")
    print("ALL PLAYWRIGHT MATRIX VISUAL TESTS PASSED (100%)!")
    print("=================================================================")
    print("\nCONSOLE ERRORS PER PAGE (TARGET: 0):")
    total_console_errs = 0
    for page_name, errs in console_errors_by_page.items():
        count = len(errs)
        total_console_errs += count
        status = "ZERO (Clean)" if count == 0 else f"{count} ERRORS: {errs}"
        print(f"  - {page_name:<45} : {status}")

    print(f"\nTOTAL CONSOLE ERRORS ACROSS ALL PAGES: {total_console_errs}")
    assert total_console_errs == 0, f"Found {total_console_errs} console errors!"

if __name__ == "__main__":
    run_qa()
