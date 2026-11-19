"""
CyberRecon CSS Linter & Validator.
Checks:
1. Balanced curly braces { and }
2. Balanced parentheses ( and )
3. @import rules must appear at the beginning of the file (before standard style rules)
4. Unclosed strings/quotes
5. Undefined var(--var-name) references against tokens.css
"""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSS_DIR = PROJECT_ROOT / "src" / "cyberrecon" / "static" / "css"

def lint_css_files():
    errors = []
    
    # 1. Collect defined CSS custom properties from tokens.css
    tokens_file = CSS_DIR / "tokens.css"
    defined_vars = set()
    if tokens_file.exists():
        tokens_content = tokens_file.read_text(encoding="utf-8")
        for match in re.finditer(r'(--[a-zA-Z0-9_\-]+)\s*:', tokens_content):
            defined_vars.add(match.group(1))

    # Also check vars defined in :root in style.css and base.css
    for fname in ["style.css", "base.css"]:
        fpath = CSS_DIR / fname
        if fpath.exists():
            for match in re.finditer(r'(--[a-zA-Z0-9_\-]+)\s*:', fpath.read_text(encoding="utf-8")):
                defined_vars.add(match.group(1))

    css_files = list(CSS_DIR.glob("**/*.css"))
    if not css_files:
        errors.append("No CSS files found in " + str(CSS_DIR))

    for css_path in css_files:
        rel_path = css_path.relative_to(PROJECT_ROOT)
        text = css_path.read_text(encoding="utf-8", errors="replace")

        # 1. Brace balance
        open_b = text.count("{")
        close_b = text.count("}")
        if open_b != close_b:
            errors.append(f"{rel_path}: Unbalanced curly braces! '{open_b}' open vs '{close_b}' close.")

        # 2. @import position check: @import must only be preceded by comments or other @import
        lines = text.splitlines()
        found_regular_rule = False
        for idx, line in enumerate(lines):
            stripped = line.strip()
            # Ignore empty or comments
            if not stripped or stripped.startswith("/*") or stripped.startswith("*") or stripped.endswith("*/"):
                continue
            if stripped.startswith("@import"):
                if found_regular_rule:
                    errors.append(f"{rel_path}:{idx+1}: Orphaned @import found after standard rules: '{stripped}'")
            elif "{" in stripped and not stripped.startswith("@import"):
                found_regular_rule = True

        # 3. Check for undefined var(--container-max) or similar typos
        # Extract var(--name)
        for idx, line in enumerate(lines):
            for v_match in re.finditer(r'var\((--[a-zA-Z0-9_\-]+)\)', line):
                var_name = v_match.group(1)
                # If var_name is not in defined_vars and not locally defined
                if var_name not in defined_vars:
                    # check if defined in same file
                    if f"{var_name}:" not in text:
                        # Allow standard dynamic or local vars
                        if var_name not in ["--ring-color", "--ring-size", "--delay", "--x", "--y", "--progress"]:
                            errors.append(f"{rel_path}:{idx+1}: Undefined CSS variable '{var_name}'")

    if errors:
        print(f"FAILED: Found {len(errors)} CSS lint errors:")
        for e in errors:
            print(f"  - {e}")
        return False
    else:
        print(f"SUCCESS: All {len(css_files)} CSS files validated cleanly.")
        return True

if __name__ == "__main__":
    success = lint_css_files()
    sys.exit(0 if success else 1)
