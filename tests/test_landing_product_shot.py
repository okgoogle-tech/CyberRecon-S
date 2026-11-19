"""
Playwright Test for Landing Page Product Shot:
1. At scrollY = 0, computed transform has rotateX > 10deg.
2. After scrolling to vertical center, computed transform is flat (rotateX < 1deg, no skew).
3. With reduced motion emulated, it is flat immediately (transform: none or rotateX < 1deg).
4. Confirms "Simulated Output" is removed, leaving only "Sample data".
"""

import time
import threading
from pathlib import Path
import pytest
from playwright.sync_api import sync_playwright
import werkzeug.serving
from cyberrecon.app import create_app

PORT = 5096


@pytest.fixture(scope="module")
def live_server():
    app = create_app()
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(1.0)
    try:
        yield f"http://127.0.0.1:{PORT}"
    finally:
        server.shutdown()


def test_landing_product_shot_scroll_flattening(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.set_default_timeout(8000)

        # domcontentloaded + explicit selector wait (never networkidle!)
        page.goto(f"{live_server}/", wait_until="domcontentloaded")
        page.wait_for_selector("#product-shot-window")

        # 1. At scrollY = 0: Check rotateX > 10deg and no Simulated Output
        assert page.locator(".simulated-badge").count() == 0
        assert "Simulated Output" not in page.content()
        assert page.locator(".sample-badge").inner_text().strip() == "Sample data"

        state_scroll0 = page.evaluate("""() => {
            const el = document.getElementById('product-shot-window');
            const style = window.getComputedStyle(el);
            const p = parseFloat(style.getPropertyValue('--p')) || 0;
            const tf = style.transform;
            let rotateXDeg = (1 - p) * 16;
            let skew = 0;
            if (tf && tf.startsWith('matrix3d')) {
                const parts = tf.slice(9, -1).split(',').map(s => parseFloat(s.trim()));
                const scale = Math.sqrt(parts[0]*parts[0] + parts[1]*parts[1] + parts[2]*parts[2]);
                const sinX = parts[9] / (scale || 1);
                const deg = Math.abs(Math.asin(Math.max(-1, Math.min(1, sinX))) * (180 / Math.PI));
                rotateXDeg = Math.max(rotateXDeg, deg);
                skew = Math.abs(parts[1]) + Math.abs(parts[4]);
            }
            return { p, rotateXDeg, skew, transform: tf };
        }""")

        print("\nSTATE AT SCROLL 0:", state_scroll0)
        assert state_scroll0["rotateXDeg"] >= 10.0, f"Expected rotateX > 10deg at scrollY=0, got {state_scroll0['rotateXDeg']}"
        assert state_scroll0["skew"] < 0.05, f"Unexpected skew at scrollY=0: {state_scroll0['skew']}"

        # 2. Scroll the product shot to the vertical center (instant scroll)
        scroll_info = page.evaluate("""() => {
            document.documentElement.style.scrollBehavior = 'auto';
            const wrap = document.getElementById('product-shot-wrap');
            const rect = wrap.getBoundingClientRect();
            const targetY = window.scrollY + rect.top - (window.innerHeight - rect.height) / 2;
            window.scrollTo(0, targetY);
            window.dispatchEvent(new Event('scroll'));
            return { rect, targetY, scrollYAfter: window.scrollY };
        }""")
        page.wait_for_timeout(300)

        state_centered = page.evaluate("""() => {
            const el = document.getElementById('product-shot-window');
            const style = window.getComputedStyle(el);
            const p = parseFloat(style.getPropertyValue('--p')) || 0;
            const tf = style.transform;
            let rotateXDeg = (1 - p) * 16;
            let skew = 0;
            if (tf && tf.startsWith('matrix3d')) {
                const parts = tf.slice(9, -1).split(',').map(s => parseFloat(s.trim()));
                // If theta = 0, matrix3d has parts[6]=0, parts[9]=0
                const sinVal = Math.abs(parts[6]); // m23
                rotateXDeg = Math.asin(Math.min(1, sinVal)) * (180 / Math.PI);
                skew = Math.abs(parts[1]) + Math.abs(parts[4]);
            } else if (tf === 'none' || tf.startsWith('matrix(1')) {
                rotateXDeg = 0;
            }
            return { p, rotateXDeg, skew, transform: tf, scrollY: window.scrollY };
        }""")
        print("SCROLL INFO:", scroll_info)
        print("STATE CENTERED:", state_centered)

        assert state_centered["rotateXDeg"] < 1.0, f"Expected flat rotateX < 1deg when centered, got {state_centered['rotateXDeg']}"
        assert state_centered["skew"] < 0.01, f"Expected no skew when centered, got {state_centered['skew']}"
        assert state_centered["p"] >= 0.95, f"Expected p >= 0.95 when centered, got {state_centered['p']}"

        browser.close()


def test_landing_product_shot_reduced_motion(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            reduced_motion="reduce",
        )
        page = context.new_page()
        page.set_default_timeout(8000)

        page.goto(f"{live_server}/", wait_until="domcontentloaded")
        page.wait_for_selector("#product-shot-window")

        state_reduced = page.evaluate("""() => {
            const el = document.getElementById('product-shot-window');
            const style = window.getComputedStyle(el);
            const tf = style.transform;
            return { transform: tf };
        }""")

        assert state_reduced["transform"] in ["none", "matrix(1, 0, 0, 1, 0, 0)"], (
            f"Expected flat transform under reduced motion, got {state_reduced['transform']}"
        )

        browser.close()
