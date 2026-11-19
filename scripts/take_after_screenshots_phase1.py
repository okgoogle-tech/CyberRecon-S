import os
import sys
import time
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import werkzeug.serving
from playwright.sync_api import sync_playwright

from cyberrecon.app import create_app
from cyberrecon.storage import create_user, get_user_by_email

OUTPUT_DIR = PROJECT_ROOT / "audit_screenshots" / "after"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
INTERACTIONS_DIR = OUTPUT_DIR / "interactions"
INTERACTIONS_DIR.mkdir(parents=True, exist_ok=True)
VIDEO_DIR = OUTPUT_DIR / "recordings"
VIDEO_DIR.mkdir(parents=True, exist_ok=True)

PORT = 5056
BASE_URL = f"http://127.0.0.1:{PORT}"

def ensure_test_user():
    user = get_user_by_email("test@cyberrecon.local")
    if not user:
        from werkzeug.security import generate_password_hash
        pwd_hash = generate_password_hash("CyberRecon123!")
        create_user("testauditor", "test@cyberrecon.local", pwd_hash)

def run_server():
    app = create_app({"TESTING": True, "CSRF_PROTECTION_ENABLED": False})
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    server.serve_forever()

def capture_phase1():
    ensure_test_user()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)

    viewports = [
        ("desktop_1440", 1440, 900),
        ("tablet_1024", 1024, 768),
        ("mobile_390", 390, 844),
    ]

    routes = [
        ("landing", "/"),
        ("about", "/about"),
    ]

    themes = ["dark", "light"]

    print("Starting Playwright capture for Phase 1 & 1B...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # 1. Standard Viewport & Theme Matrices
        for vp_name, width, height in viewports:
            for theme in themes:
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    color_scheme=theme,
                )
                page = context.new_page()

                for page_name, route in routes:
                    target_url = f"{BASE_URL}{route}"
                    page.goto(target_url)
                    page.wait_for_load_state("networkidle")

                    page.evaluate(f"""() => {{
                        document.documentElement.setAttribute('data-theme', '{theme}');
                        localStorage.setItem('cyberrecon-theme', '{theme}');
                    }}""")
                    time.sleep(0.3)

                    filename = f"after_{page_name}_{vp_name}_{theme}.png"
                    filepath = OUTPUT_DIR / filename
                    page.screenshot(path=str(filepath), full_page=True)
                    print(f"[CAPTURED] {filename} ({width}x{height}, {theme})")

                context.close()

        # 2. Key Interactive & Animation Demonstrations with Video Recording
        print("\nCapturing interactive features & motion recording...")
        video_context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            color_scheme="dark",
            record_video_dir=str(VIDEO_DIR),
            record_video_size={"width": 1440, "height": 900},
        )
        page = video_context.new_page()

        # A. Landing Hero: Spotlight and Product Shot Tilt
        page.goto(f"{BASE_URL}/")
        page.wait_for_load_state("networkidle")
        time.sleep(0.5)

        # Move mouse across hero to demonstrate spotlight and 3D parallax
        for x in [300, 720, 1100, 720]:
            page.mouse.move(x, 350)
            time.sleep(0.2)
        
        page.screenshot(path=str(INTERACTIONS_DIR / "interaction_spotlight_hero.png"))
        print("[CAPTURED] interaction_spotlight_hero.png")

        # Scroll down to demonstrate tilt-to-flat transition
        page.evaluate("window.scrollTo({ top: 350, behavior: 'smooth' })")
        time.sleep(0.8)
        page.screenshot(path=str(INTERACTIONS_DIR / "interaction_product_shot_flat.png"))
        print("[CAPTURED] interaction_product_shot_flat.png")

        # Scroll to How It Works signal line
        page.evaluate("window.scrollTo({ top: 900, behavior: 'smooth' })")
        time.sleep(0.8)
        page.screenshot(path=str(INTERACTIONS_DIR / "interaction_signal_line_steps.png"))
        print("[CAPTURED] interaction_signal_line_steps.png")

        # B. About Page: Interactive What-If Simulator & Remediations
        page.goto(f"{BASE_URL}/about")
        page.wait_for_load_state("networkidle")
        time.sleep(0.5)

        # Expand Check CR-001 to show Remediation code tabs
        cr001_header = page.locator("#check-cr-001 .check-row-header")
        if cr001_header.count() > 0:
            cr001_header.click()
            time.sleep(0.4)
            # Switch tab to express
            express_tab = page.locator("#check-cr-001 button[data-tab='express']")
            if express_tab.count() > 0:
                express_tab.click()
                time.sleep(0.3)
            page.screenshot(path=str(INTERACTIONS_DIR / "interaction_check_expanded_remediation.png"))
            print("[CAPTURED] interaction_check_expanded_remediation.png")

        # Scroll to What-If Simulator
        simulator = page.locator("#simulator")
        if simulator.count() > 0:
            simulator.scroll_into_view_if_needed()
            time.sleep(0.5)
            # Add medium findings to see the live score drop
            btn_add_med = page.locator("#btn-add-medium")
            if btn_add_med.count() > 0:
                btn_add_med.click()
                time.sleep(0.2)
                btn_add_med.click()
                time.sleep(0.3)
            page.screenshot(path=str(INTERACTIONS_DIR / "interaction_simulator_score_live.png"))
            print("[CAPTURED] interaction_simulator_score_live.png")

        # Expand FAQ Accordion item
        faq_btn = page.locator(".faq-question-btn").first
        if faq_btn.count() > 0:
            faq_btn.scroll_into_view_if_needed()
            faq_btn.click()
            time.sleep(0.4)
            page.screenshot(path=str(INTERACTIONS_DIR / "interaction_faq_accordion.png"))
            print("[CAPTURED] interaction_faq_accordion.png")

        video_context.close()

        # C. Mobile Drawer Interaction at 390px
        mobile_context = browser.new_context(
            viewport={"width": 390, "height": 844},
            color_scheme="dark",
        )
        m_page = mobile_context.new_page()
        m_page.goto(f"{BASE_URL}/")
        m_page.wait_for_load_state("networkidle")
        time.sleep(0.3)

        mobile_btn = m_page.locator("#mobile-menu-btn")
        if mobile_btn.count() > 0:
            mobile_btn.click()
            time.sleep(0.4)
            m_page.screenshot(path=str(INTERACTIONS_DIR / "interaction_mobile_drawer_open_390.png"))
            print("[CAPTURED] interaction_mobile_drawer_open_390.png")

        mobile_context.close()
        browser.close()

    print("\nALL AFTER SCREENSHOTS & RECORDINGS CAPTURED SUCCESSFULLY!")

if __name__ == "__main__":
    capture_phase1()
