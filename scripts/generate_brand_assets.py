import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parents[1]
IMG_DIR = PROJECT_ROOT / "src" / "cyberrecon" / "static" / "img"
IMG_DIR.mkdir(parents=True, exist_ok=True)

SVG_CONTENT = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none">
    <defs>
        <linearGradient id="g" x1="4" y1="4" x2="28" y2="28" gradientUnits="userSpaceOnUse">
            <stop stop-color="#34d399"/>
            <stop offset="1" stop-color="#22d3ee"/>
        </linearGradient>
    </defs>
    <path d="M25.53 10.5A11 11 0 1 0 25.53 21.5" stroke="url(#g)" stroke-width="3" stroke-linecap="round"/>
    <circle cx="16" cy="16" r="3" fill="url(#g)"/>
</svg>"""

SVG_PATH = IMG_DIR / "favicon.svg"
SVG_PATH.write_text(SVG_CONTENT, encoding="utf-8")
print(f"Wrote {SVG_PATH}")

def render_assets():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        # 1. 32px favicon
        page = browser.new_page(viewport={"width": 32, "height": 32})
        page.set_content(f"""<!DOCTYPE html><html><body style="margin:0;padding:0;background:transparent;overflow:hidden;">{SVG_CONTENT}</body></html>""")
        page.screenshot(path=str(IMG_DIR / "favicon-32.png"), omit_background=True)
        print("Generated favicon-32.png")
        page.close()

        # 2. 180px apple-touch-icon
        page = browser.new_page(viewport={"width": 180, "height": 180})
        page.set_content(f"""<!DOCTYPE html><html><body style="margin:0;padding:20px;background:#05080f;display:flex;align-items:center;justify-content:center;box-sizing:border-box;">{SVG_CONTENT}</body></html>""")
        page.screenshot(path=str(IMG_DIR / "apple-touch-icon.png"))
        print("Generated apple-touch-icon.png")
        page.close()

        # 3. 1200x630 OG image
        page = browser.new_page(viewport={"width": 1200, "height": 630})
        page.set_content(f"""<!DOCTYPE html>
<html>
<head>
<style>
body {{
    margin: 0;
    padding: 0;
    width: 1200px;
    height: 630px;
    background: radial-gradient(circle at 50% 0%, #101a2d 0%, #05080f 70%);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: #f8fafc;
    text-align: center;
}}
.logo-wrap {{
    width: 120px;
    height: 120px;
    margin-bottom: 24px;
}}
.brand {{
    font-size: 56px;
    font-weight: 800;
    letter-spacing: -0.03em;
    margin-bottom: 16px;
}}
.brand .recon {{
    color: #34d399;
}}
.tagline {{
    font-size: 24px;
    color: #94a3b8;
    max-width: 700px;
    line-height: 1.4;
}}
.pill {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 16px;
    border-radius: 9999px;
    background: rgba(52, 211, 153, 0.1);
    border: 1px solid rgba(52, 211, 153, 0.3);
    color: #34d399;
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 28px;
}}
</style>
</head>
<body>
    <div class="pill">Passive Security Reconnaissance</div>
    <div class="logo-wrap">{SVG_CONTENT}</div>
    <div class="brand">Cyber<span class="recon">Recon</span></div>
    <div class="tagline">Non-intrusive, authorized passive web reconnaissance and configuration posture assessment.</div>
</body>
</html>""")
        page.screenshot(path=str(IMG_DIR / "og-image.png"))
        print("Generated og-image.png")
        page.close()

        browser.close()

if __name__ == "__main__":
    render_assets()
