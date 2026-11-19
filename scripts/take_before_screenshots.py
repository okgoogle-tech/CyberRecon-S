import os
import sys
import time
import threading
from pathlib import Path

# Set up paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import werkzeug.serving
from playwright.sync_api import sync_playwright

from cyberrecon.app import create_app
from cyberrecon.storage import create_user, get_user_by_email, get_connection

OUTPUT_DIR = PROJECT_ROOT / "audit_screenshots" / "before"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PORT = 5055
BASE_URL = f"http://127.0.0.1:{PORT}"

def ensure_test_user():
    user = get_user_by_email("test@cyberrecon.local")
    if not user:
        from werkzeug.security import generate_password_hash
        pwd_hash = generate_password_hash("CyberRecon123!")
        create_user("testauditor", "test@cyberrecon.local", pwd_hash)
        print("Created test user: test@cyberrecon.local / CyberRecon123!")

def run_server():
    app = create_app({"TESTING": True, "CSRF_PROTECTION_ENABLED": False})
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    server.serve_forever()

def capture_all():
    ensure_test_user()
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.5) # Wait for server startup

    viewports = [
        ("desktop_1440", 1440, 900),
        ("tablet_1024", 1024, 768),
        ("mobile_390", 390, 844),
    ]

    routes = [
        ("landing", "/"),
        ("dashboard", "/dashboard"),
        ("new_assessment", "/new"),
        ("history", "/history"),
        ("compare", "/compare"),
    ]

    themes = ["dark", "light"]

    print("Starting Playwright capture...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        for vp_name, width, height in viewports:
            for theme in themes:
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    color_scheme=theme,
                )
                page = context.new_page()

                # Log in first for authenticated pages
                page.goto(f"{BASE_URL}/login")
                page.fill("input[name='email']", "test@cyberrecon.local")
                page.fill("input[name='password']", "CyberRecon123!")
                page.click("button[type='submit']")
                page.wait_for_load_state("networkidle")

                for page_name, route in routes:
                    target_url = f"{BASE_URL}{route}"
                    page.goto(target_url)
                    page.wait_for_load_state("networkidle")
                    
                    # Ensure theme attribute is explicitly set on documentElement
                    page.evaluate(f"""() => {{
                        document.documentElement.setAttribute('data-theme', '{theme}');
                        localStorage.setItem('cyberrecon-theme', '{theme}');
                    }}""")
                    time.sleep(0.3)

                    filename = f"before_{page_name}_{vp_name}_{theme}.png"
                    filepath = OUTPUT_DIR / filename
                    page.screenshot(path=str(filepath), full_page=True)
                    print(f"[CAPTURED] {filename} ({width}x{height}, {theme})")

                context.close()
        browser.close()

    print("\nALL BEFORE SCREENSHOTS CAPTURED SUCCESSFULLY!")

if __name__ == "__main__":
    capture_all()
