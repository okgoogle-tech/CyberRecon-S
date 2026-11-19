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
)
from scripts.seed_demo import seed_demo_data, DEMO_EMAIL, DEMO_PASSWORD

PORT = 5092
BASE_URL = f"http://127.0.0.1:{PORT}"

def run_server(server):
    server.serve_forever()

def diagnose():
    initialize_database()
    seed_demo_data()

    app = create_app()
    server = werkzeug.serving.make_server("127.0.0.1", PORT, app)
    srv_thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    srv_thread.start()
    time.sleep(1.0)

    print("Server started on", BASE_URL)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        pages_to_check = [
            ("/", "Landing Page"),
            ("/about", "About Page"),
            ("/dashboard", "Dashboard Page (auth required)"),
        ]

        for path, label in pages_to_check:
            print(f"\n==========================================")
            print(f"DIAGNOSING: {label} ({path})")
            print(f"==========================================")

            context = browser.new_context(viewport={"width": 1440, "height": 900})
            page = context.new_page()

            network_requests = []
            failed_requests = []
            console_messages = []

            def on_request(req):
                network_requests.append(req.url)

            def on_response(res):
                if res.status >= 400:
                    failed_requests.append((res.url, res.status, res.status_text))

            def on_request_failed(req):
                failed_requests.append((req.url, "FAILED", req.failure))

            def on_console(msg):
                console_messages.append((msg.type, msg.text))

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfailed", on_request_failed)
            page.on("console", on_console)

            # If dashboard, login first
            if path == "/dashboard":
                page.goto(f"{BASE_URL}/login")
                page.fill("input[name='email']", DEMO_EMAIL)
                page.fill("input[name='password']", DEMO_PASSWORD)
                page.click("button[type='submit']")
                page.wait_for_load_state("networkidle")

            page.goto(f"{BASE_URL}{path}")
            page.wait_for_load_state("networkidle")
            time.sleep(1.0)

            # 1. Stylesheets linked in DOM
            css_links = page.evaluate("""() => {
                const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));
                return links.map(l => ({ href: l.href, outerHTML: l.outerHTML }));
            }""")
            print("\n[CSS LINKS IN DOM]:")
            for link in css_links:
                print(f"  - {link['href']}")

            # 2. Failed network requests
            print(f"\n[FAILED NETWORK REQUESTS] ({len(failed_requests)}):")
            for item in failed_requests:
                print(f"  FAILED: {item}")

            # 3. Console messages
            print(f"\n[CONSOLE MESSAGES] ({len(console_messages)}):")
            for msg_type, msg_text in console_messages:
                print(f"  [{msg_type}] {msg_text}")

            # 4. Horizontal overflow check
            overflow = page.evaluate("""() => {
                const doc = document.documentElement;
                return {
                    scrollWidth: doc.scrollWidth,
                    clientWidth: doc.clientWidth,
                    hasOverflow: doc.scrollWidth > doc.clientWidth
                };
            }""")
            print(f"\n[OVERFLOW]: scrollWidth={overflow['scrollWidth']}, clientWidth={overflow['clientWidth']}, hasOverflow={overflow['hasOverflow']}")

            # 5. Clipped past left edge check
            clipped = page.evaluate("""() => {
                const all = Array.from(document.querySelectorAll('*'));
                const clippedElements = [];
                for (const el of all) {
                    const rect = el.getBoundingClientRect();
                    if (rect.left < -1 && rect.width > 0 && rect.height > 0) {
                        clippedElements.push({
                            tag: el.tagName,
                            id: el.id,
                            className: el.className,
                            left: rect.left,
                            text: el.innerText ? el.innerText.slice(0, 30) : ''
                        });
                    }
                }
                return clippedElements;
            }""")
            print(f"\n[CLIPPED PAST LEFT EDGE] ({len(clipped)}):")
            for c in clipped[:5]:
                print(f"  {c}")

            # 6. Specific page checks
            if path == "/":
                h1_style = page.evaluate("""() => {
                    const h1 = document.querySelector('h1');
                    if (!h1) return 'NO H1';
                    const s = window.getComputedStyle(h1);
                    return { textAlign: s.textAlign, fontSize: s.fontSize, lineHeight: s.lineHeight };
                }""")
                print(f"\n[LANDING H1 STYLE]: {h1_style}")

                error_msg_vis = page.evaluate("""() => {
                    const err = document.querySelector('#hero-inline-error');
                    if (!err) return 'NO ERROR EL';
                    const s = window.getComputedStyle(err);
                    return { display: s.display, visibility: s.visibility, opacity: s.opacity, height: s.offsetHeight };
                }""")
                print(f"[LANDING ERROR MSG VISIBILITY ON LOAD]: {error_msg_vis}")

            if path == "/dashboard":
                nav_main_align = page.evaluate("""() => {
                    const nav = document.querySelector('.navbar .nav-container, header .container');
                    const main = document.querySelector('main.container, .dashboard-main-container');
                    return {
                        navRect: nav ? nav.getBoundingClientRect() : null,
                        mainRect: main ? main.getBoundingClientRect() : null
                    };
                }""")
                print(f"\n[NAV vs MAIN ALIGNMENT]: {nav_main_align}")

            context.close()

        browser.close()

    server.shutdown()
    print("\nDiagnosis completed.")

if __name__ == "__main__":
    diagnose()
