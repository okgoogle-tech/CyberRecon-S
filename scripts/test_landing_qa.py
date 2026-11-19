import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

import threading, time
import werkzeug.serving
from playwright.sync_api import sync_playwright
from cyberrecon.app import create_app

PORT = 5096
BASE_URL = f"http://127.0.0.1:{PORT}"

def test_landing():
    app = create_app()
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(1.0)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        viewports = [
            ("Desktop 1440", 1440, 900),
            ("Tablet 1024", 1024, 768),
            ("Mobile 390", 390, 844),
        ]

        for vp_name, w, h in viewports:
            print(f"\n--- Testing Landing at {vp_name} ---")
            page = browser.new_page(viewport={"width": w, "height": h})
            page.goto(f"{BASE_URL}/")
            page.wait_for_load_state("networkidle")

            # 1. Nav vs Main alignment
            nav = page.locator(".navbar .nav-container").bounding_box()
            main = page.locator("main.container").bounding_box()
            print(f"  Nav left={nav['x']}, right={nav['x']+nav['width']}, width={nav['width']}")
            print(f"  Main left={main['x']}, right={main['x']+main['width']}, width={main['width']}")
            assert abs(nav['x'] - main['x']) <= 1.0, f"Nav left ({nav['x']}) does not match Main left ({main['x']})"
            assert abs(nav['width'] - main['width']) <= 1.0, f"Nav width ({nav['width']}) does not match Main width ({main['width']})"

            # 2. No horizontal overflow
            overflow = page.evaluate("() => document.documentElement.scrollWidth > document.documentElement.clientWidth")
            assert not overflow, f"Horizontal overflow detected at {vp_name}!"

            # 3. H1 centered
            h1_align = page.evaluate("() => window.getComputedStyle(document.querySelector('h1')).textAlign")
            assert h1_align == "center", f"H1 is not centered! text-align: {h1_align}"

            # 4. Error message hidden on load
            error_display = page.evaluate("() => window.getComputedStyle(document.querySelector('#hero-error-msg')).display")
            assert error_display == "none", f"Error message is visible on load! display: {error_display}"

            # 5. 3-column check at 1024px+
            if w >= 1024:
                cols = page.evaluate("() => window.getComputedStyle(document.querySelector('.landing-values-grid')).gridTemplateColumns.split(' ').length")
                assert cols == 3, f"Expected 3 columns for value cards at {w}px, got {cols}"

            # 6. Banned strings check
            body_text = page.locator("body").inner_text()
            banned = ["Observed Findings", "Failed Probes", "Operational Security Insights", "Common Findings Intelligence", "Simulated Output"]
            for b in banned:
                assert b not in body_text, f"Banned string '{b}' found in page text!"

            print(f"  All Landing assertions passed at {vp_name}!")
            page.close()

        browser.close()
    server.shutdown()
    print("\nLanding page test PASSED 100%!")

if __name__ == "__main__":
    test_landing()
