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

from cyberrecon.app import create_app
from cyberrecon.storage import initialize_database
from scripts.seed_demo import seed_demo_data, DEMO_EMAIL, DEMO_PASSWORD

PORT = 5094
BASE_URL = f"http://127.0.0.1:{PORT}"

def run_server(server):
    server.serve_forever()

def check_dashboard_clipping():
    initialize_database()
    seed_demo_data()

    app = create_app()
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    srv_thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    srv_thread.start()
    time.sleep(1.0)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        viewports = [
            ("Desktop 1440", 1440, 900),
            ("Tablet 1024", 1024, 768),
            ("Mobile 390", 390, 844),
        ]

        for vp_name, width, height in viewports:
            print(f"\n--- Checking {vp_name} ---")
            context = browser.new_context(viewport={"width": width, "height": height})
            page = context.new_page()

            # Login
            page.goto(f"{BASE_URL}/login")
            page.fill("input[name='email']", DEMO_EMAIL)
            page.fill("input[name='password']", DEMO_PASSWORD)
            page.click("button[type='submit']")
            page.wait_for_load_state("networkidle")

            # Go to dashboard with a filter so active filters chip is visible
            page.goto(f"{BASE_URL}/dashboard?range=7d")
            page.wait_for_load_state("networkidle")

            # Check positions
            elements = page.evaluate("""() => {
                const results = {};
                const selectors = {
                    navbar: '.navbar',
                    nav_container: '.navbar .nav-container',
                    main: 'main.container',
                    cmd_header: '.cmd-header',
                    cmd_title: '.cmd-title',
                    filter_chips: '.filter-chips-row',
                    body: 'body'
                };
                for (const [key, sel] of Object.entries(selectors)) {
                    const el = document.querySelector(sel);
                    if (el) {
                        const r = el.getBoundingClientRect();
                        results[key] = { left: r.left, right: r.right, width: r.width, x: r.x };
                    } else {
                        results[key] = 'NOT FOUND';
                    }
                }
                return results;
            }""")
            for k, v in elements.items():
                print(f"  {k}: {v}")

            # Check if any element has left < 0
            clipped = page.evaluate("""() => {
                const bad = [];
                for (const el of document.querySelectorAll('*')) {
                    const r = el.getBoundingClientRect();
                    if (r.left < 0 && r.width > 0 && r.height > 0) {
                        bad.push({
                            tag: el.tagName,
                            class: el.className,
                            left: r.left,
                            text: el.innerText ? el.innerText.slice(0, 30) : ''
                        });
                    }
                }
                return bad;
            }""")
            if clipped:
                print(f"  CLIPPED ELEMENTS ({len(clipped)}):")
                for c in clipped[:5]:
                    print(f"    {c}")
            else:
                print("  No elements with left < 0")

            context.close()

        browser.close()
    server.shutdown()

if __name__ == "__main__":
    check_dashboard_clipping()
