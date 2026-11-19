"""
CyberRecon Posture Scoring and Security Check Registry Engine.

Version: v1.1-diminishing
Calculates deterministic security posture scores (0-100), letter grades,
and category breakdowns strictly derived from real passive assessment findings.
Uses diminishing returns per severity and category caps so that minor findings
do not disproportionately penalize overall posture.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

SCORE_VERSION = "v1.2-unencrypted-cap"

# =========================================================
# SEVERITY WEIGHTS & DIMINISHING RETURNS
# =========================================================

# Diminishing penalties per severity:
# High: 20 pts (e.g. plain HTTP without TLS)
# Medium: 8 pts (1st), 6 pts (2nd), 4 pts (3rd+)
# Low: 3 pts (1st), 2 pts (2nd), 1 pt (3rd+)
# Info: 0 pts (Informational only)
# Pass: 0 pts
SEVERITY_TIERS: Dict[str, List[int]] = {
    "High": [20, 15, 10], # default to last value for subsequent
    "Medium": [8, 6, 4],
    "Low": [3, 2, 1],
    "Info": [0],
}

CATEGORY_CAPS: Dict[str, int] = {
    "Transport Security": 25,
    "Browser Security": 35,
    "Privacy and Browser Security": 15,
    "Cross-Origin Security": 15,
    "Information Disclosure": 10,
    "Session Security": 20,
}

GRADE_THRESHOLDS: List[Tuple[int, str, str]] = [
    (90, "A", "Optimal Posture"),
    (80, "B", "Good Posture"),
    (70, "C", "Fair Posture"),
    (60, "D", "Elevated Risk"),
    (0, "F", "Critical Deficiencies"),
]

# Standard 4 High-Level Assessment Categories strictly from Registry
CATEGORY_MAPPING: Dict[str, str] = {
    "Transport Security": "Transport Security",
    "Browser Security": "Browser & Headers",
    "Privacy and Browser Security": "Browser & Headers",
    "Cross-Origin Security": "Cross-Origin Security",
    "Information Disclosure": "Session & Disclosure",
    "Session Security": "Session & Disclosure",
}

# Real 18 Canonical Security Checks in the Registry (No check emits Critical)
CHECK_REGISTRY: List[Dict[str, Any]] = [
    {
        "id": "CR-001",
        "name": "HTTPS Not Enabled",
        "category": "Transport Security",
        "high_level_category": "Transport Security",
        "severity": "High",
        "cwe": "CWE-319",
        "owasp": "OWASP A02:2021 Cryptographic Failures",
        "why_it_matters": "Traffic delivered without HTTPS is transmitted in plaintext, exposing session credentials, tokens, and data to interception, eavesdropping, and on-path manipulation.",
        "how_evaluated": "Verifies whether the final assessed URL uses TLS encryption (https://) and that plain HTTP traffic is redirected.",
        "remediation": {
            "nginx": "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}",
            "apache": "<VirtualHost *:80>\n    ServerName example.com\n    Redirect permanent / https://example.com/\n</VirtualHost>",
            "express": "app.use((req, res, next) => {\n    if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();\n    res.redirect(301, 'https://' + req.headers.host + req.url);\n});",
        },
    },
    {
        "id": "CR-002",
        "name": "HSTS Header Missing or Disabled",
        "category": "Transport Security",
        "high_level_category": "Transport Security",
        "severity": "Medium",
        "cwe": "CWE-319",
        "owasp": "OWASP A02:2021 Cryptographic Failures",
        "why_it_matters": "HTTP Strict Transport Security (HSTS) prevents SSL-stripping man-in-the-middle attacks by forcing browsers to connect only via HTTPS.",
        "how_evaluated": "Checks for the presence of the Strict-Transport-Security response header and verifies max-age is greater than 0.",
        "remediation": {
            "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
            "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            "express": "const helmet = require('helmet');\napp.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
        },
    },
    {
        "id": "CR-003",
        "name": "Content Security Policy Missing",
        "category": "Browser Security",
        "high_level_category": "Browser & Headers",
        "severity": "Medium",
        "cwe": "CWE-693",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "CSP restricts script, style, and object execution sources, providing defense-in-depth against Cross-Site Scripting (XSS) and data injection.",
        "how_evaluated": "Checks for an enforced Content-Security-Policy response header.",
        "remediation": {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;",
            "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"",
            "express": "const helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy());",
        },
    },
    {
        "id": "CR-004",
        "name": "Clickjacking Protection Missing",
        "category": "Browser Security",
        "high_level_category": "Browser & Headers",
        "severity": "Medium",
        "cwe": "CWE-1021",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Without framing restrictions, malicious sites can embed the application in an invisible iframe to trick users into unintended clicks.",
        "how_evaluated": "Checks for X-Frame-Options (DENY or SAMEORIGIN) or CSP frame-ancestors directive.",
        "remediation": {
            "nginx": "add_header X-Frame-Options \"DENY\" always;\n# Or in CSP:\nadd_header Content-Security-Policy \"frame-ancestors 'none';\" always;",
            "apache": "Header always set X-Frame-Options \"DENY\"",
            "express": "const helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));",
        },
    },
    {
        "id": "CR-005",
        "name": "MIME Sniffing Protection Missing",
        "category": "Browser Security",
        "high_level_category": "Browser & Headers",
        "severity": "Low",
        "cwe": "CWE-693",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Prevents browsers from interpreting user-uploaded non-executable files (like images) as HTML/JavaScript.",
        "how_evaluated": "Checks for X-Content-Type-Options: nosniff header.",
        "remediation": {
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": "Header always set X-Content-Type-Options \"nosniff\"",
            "express": "const helmet = require('helmet');\napp.use(helmet.noSniff());",
        },
    },
    {
        "id": "CR-006",
        "name": "Web Server Information Disclosed",
        "category": "Information Disclosure",
        "high_level_category": "Session & Disclosure",
        "severity": "Info",
        "cwe": "CWE-200",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Revealing the web server brand and exact version string helps attackers target known CVE vulnerabilities.",
        "how_evaluated": "Examines the Server header for specific version and product names.",
        "remediation": {
            "nginx": "server_tokens off;",
            "apache": "ServerTokens Prod\nServerSignature Off",
            "express": "app.disable('x-powered-by');",
        },
    },
    {
        "id": "CR-007",
        "name": "Technology Information Disclosed",
        "category": "Information Disclosure",
        "high_level_category": "Session & Disclosure",
        "severity": "Low",
        "cwe": "CWE-200",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Reveals backend frameworks (PHP, Express, ASP.NET) via X-Powered-By, facilitating targeted exploits.",
        "how_evaluated": "Checks for X-Powered-By or X-AspNet-Version response headers.",
        "remediation": {
            "nginx": "proxy_hide_header X-Powered-By;",
            "apache": "Header unset X-Powered-By",
            "express": "app.disable('x-powered-by');",
        },
    },
    {
        "id": "CR-008",
        "name": "Referrer Policy Missing",
        "category": "Privacy and Browser Security",
        "high_level_category": "Browser & Headers",
        "severity": "Low",
        "cwe": "CWE-200",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Without an explicit referrer policy, sensitive URLs containing IDs or tokens may leak to third-party domains.",
        "how_evaluated": "Checks for the Referrer-Policy header.",
        "remediation": {
            "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            "express": "const helmet = require('helmet');\napp.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        },
    },
    {
        "id": "CR-009",
        "name": "Permissions Policy Missing",
        "category": "Browser Security",
        "high_level_category": "Browser & Headers",
        "severity": "Info",
        "cwe": "CWE-693",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Permissions-Policy allows developers to selectively disable powerful browser APIs (camera, microphone, geolocation).",
        "how_evaluated": "Checks for the Permissions-Policy response header.",
        "remediation": {
            "nginx": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            "apache": "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
            "express": "app.use((req, res, next) => {\n    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');\n    next();\n});",
        },
    },
    {
        "id": "CR-010",
        "name": "Unsafe Referrer Policy",
        "category": "Privacy and Browser Security",
        "high_level_category": "Browser & Headers",
        "severity": "Low",
        "cwe": "CWE-200",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Policies like 'unsafe-url' leak complete URL query strings to external resources on every outbound request.",
        "how_evaluated": "Detects if Referrer-Policy is set to unsafe-url or no-referrer-when-downgrade.",
        "remediation": {
            "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            "express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        },
    },
    {
        "id": "CR-011",
        "name": "Potentially Weak CSP Directive",
        "category": "Browser Security",
        "high_level_category": "Browser & Headers",
        "severity": "Medium",
        "cwe": "CWE-693",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Directives allowing 'unsafe-inline' or 'unsafe-eval' neutralize XSS protections offered by CSP.",
        "how_evaluated": "Scans CSP directives for unsafe-inline, unsafe-eval, or data: script sources.",
        "remediation": {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
            "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self';\"",
            "express": "app.use(helmet.contentSecurityPolicy({ directives: { scriptSrc: [\"'self'\", (req, res) => `'nonce-${res.locals.cspNonce}'`] } }));",
        },
    },
    {
        "id": "CR-012",
        "name": "Wildcard CORS Policy Detected",
        "category": "Cross-Origin Security",
        "high_level_category": "Cross-Origin Security",
        "severity": "Low",
        "cwe": "CWE-942",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Access-Control-Allow-Origin: * allows any web origin to read responses if authentication headers or credentials overlap.",
        "how_evaluated": "Checks if Access-Control-Allow-Origin is set to wildcard '*' on sensitive response endpoints.",
        "remediation": {
            "nginx": "add_header Access-Control-Allow-Origin \"https://app.example.com\" always;",
            "apache": "Header always set Access-Control-Allow-Origin \"https://app.example.com\"",
            "express": "const cors = require('cors');\napp.use(cors({ origin: 'https://app.example.com', credentials: true }));",
        },
    },
    {
        "id": "CR-013",
        "name": "Cross-Origin Opener Policy Missing",
        "category": "Cross-Origin Security",
        "high_level_category": "Cross-Origin Security",
        "severity": "Info",
        "cwe": "CWE-693",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "COOP ensures a top-level document does not share a browsing context group with cross-origin documents, mitigating Spectre-class attacks.",
        "how_evaluated": "Checks for Cross-Origin-Opener-Policy: same-origin.",
        "remediation": {
            "nginx": "add_header Cross-Origin-Opener-Policy \"same-origin\" always;",
            "apache": "Header always set Cross-Origin-Opener-Policy \"same-origin\"",
            "express": "app.use(helmet.crossOriginOpenerPolicy({ policy: 'same-origin' }));",
        },
    },
    {
        "id": "CR-014",
        "name": "Cross-Origin Resource Policy Missing",
        "category": "Cross-Origin Security",
        "high_level_category": "Cross-Origin Security",
        "severity": "Info",
        "cwe": "CWE-693",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "CORP blocks cross-origin, cross-site reading of sensitive resources like images, scripts, and JSON by malicious sites.",
        "how_evaluated": "Checks for Cross-Origin-Resource-Policy header.",
        "remediation": {
            "nginx": "add_header Cross-Origin-Resource-Policy \"same-origin\" always;",
            "apache": "Header always set Cross-Origin-Resource-Policy \"same-origin\"",
            "express": "app.use(helmet.crossOriginResourcePolicy({ policy: 'same-origin' }));",
        },
    },
    {
        "id": "CR-015",
        "name": "Cross-Origin Embedder Policy Missing",
        "category": "Cross-Origin Security",
        "high_level_category": "Cross-Origin Security",
        "severity": "Info",
        "cwe": "CWE-693",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "COEP prevents a document from loading cross-origin resources that do not explicitly grant permission.",
        "how_evaluated": "Checks for Cross-Origin-Embedder-Policy: require-corp.",
        "remediation": {
            "nginx": "add_header Cross-Origin-Embedder-Policy \"require-corp\" always;",
            "apache": "Header always set Cross-Origin-Embedder-Policy \"require-corp\"",
            "express": "app.use(helmet.crossOriginEmbedderPolicy());",
        },
    },
    {
        "id": "CR-016",
        "name": "Cookie Missing Secure Flag",
        "category": "Session Security",
        "high_level_category": "Session & Disclosure",
        "severity": "Low",
        "cwe": "CWE-614",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "Cookies without the Secure attribute are sent over unencrypted HTTP connections, exposing session cookies.",
        "how_evaluated": "Inspects Set-Cookie headers for '; Secure' attribute.",
        "remediation": {
            "nginx": "proxy_cookie_flags ~ secure;",
            "apache": "Header edit Set-Cookie ^(.*)$ \"$1; Secure\"",
            "express": "res.cookie('session_id', token, { secure: true, httpOnly: true, sameSite: 'lax' });",
        },
    },
    {
        "id": "CR-017",
        "name": "Cookie Missing HttpOnly Flag",
        "category": "Session Security",
        "high_level_category": "Session & Disclosure",
        "severity": "Low",
        "cwe": "CWE-1004",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "HttpOnly prevents client-side JavaScript from accessing cookies, mitigating session hijacking via XSS.",
        "how_evaluated": "Inspects Set-Cookie headers for '; HttpOnly' attribute.",
        "remediation": {
            "nginx": "proxy_cookie_flags ~ httponly;",
            "apache": "Header edit Set-Cookie ^(.*)$ \"$1; HttpOnly\"",
            "express": "res.cookie('session_id', token, { httpOnly: true, secure: true, sameSite: 'lax' });",
        },
    },
    {
        "id": "CR-018",
        "name": "Cookie SameSite Attribute Missing",
        "category": "Session Security",
        "high_level_category": "Session & Disclosure",
        "severity": "Low",
        "cwe": "CWE-1275",
        "owasp": "OWASP A05:2021 Security Misconfiguration",
        "why_it_matters": "SameSite controls cookie inclusion on cross-site requests, providing defense against Cross-Site Request Forgery (CSRF).",
        "how_evaluated": "Inspects Set-Cookie headers for 'SameSite=Lax|Strict|None' attribute.",
        "remediation": {
            "nginx": "proxy_cookie_flags ~ samesite=lax;",
            "apache": "Header edit Set-Cookie ^(.*)$ \"$1; SameSite=Lax\"",
            "express": "res.cookie('session_id', token, { sameSite: 'lax', httpOnly: true, secure: true });",
        },
    },
]

CHECK_BY_ID: Dict[str, Dict[str, Any]] = {
    check["id"]: check for check in CHECK_REGISTRY
}


# =========================================================
# POSTURE SCORE CALCULATION (DIMINISHING RETURNS)
# =========================================================

def get_penalty_for_index(severity: str, index: int) -> int:
    """Return diminishing penalty for the n-th finding of a given severity."""
    tiers = SEVERITY_TIERS.get(severity, [0])
    if index < len(tiers):
        return tiers[index]
    return tiers[-1]


def calculate_posture_score(
    findings: List[Dict[str, Any]],
    is_http: bool = False,
    version: str = SCORE_VERSION,
) -> Dict[str, Any]:
    """
    Compute real numerical score (0-100), letter grade (A-F),
    and category breakdown using diminishing returns and category caps.
    """
    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    category_counts = {
        "Transport Security": 0,
        "Browser & Headers": 0,
        "Cross-Origin Security": 0,
        "Session & Disclosure": 0,
    }

    category_penalties: Dict[str, int] = {
        "Transport Security": 0,
        "Browser & Headers": 0,
        "Cross-Origin Security": 0,
        "Session & Disclosure": 0,
    }

    failed_check_ids = set()

    # Sort findings by severity priority: High, Medium, Low, Info
    sev_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_order.get(f.get("severity", "Info"), 99)
    )

    for finding in sorted_findings:
        sev = finding.get("severity", "Info")
        if sev not in severity_counts:
            sev = "Info"
        
        idx = severity_counts[sev]
        severity_counts[sev] += 1
        penalty = get_penalty_for_index(sev, idx)

        cid = finding.get("id") or finding.get("finding_code")
        if cid:
            failed_check_ids.add(cid)

        raw_cat = finding.get("category", "")
        hl_cat = CATEGORY_MAPPING.get(raw_cat, "Browser & Headers")
        if hl_cat in category_counts:
            category_counts[hl_cat] += 1
            category_penalties[hl_cat] += penalty

    # Apply category caps
    total_deduction = 0
    effective_category_penalties = {}
    for cat, pen in category_penalties.items():
        cap = CATEGORY_CAPS.get(cat, 35)
        effective = min(pen, cap)
        effective_category_penalties[cat] = effective
        total_deduction += effective

    score = max(0, min(100, 100 - total_deduction))

    # Determine letter grade
    grade = "F"
    label = "Critical Deficiencies"
    for threshold, g, lbl in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = g
            label = lbl
            break

    # Unencrypted HTTP Handling & Capping (v1.2+)
    na_check_ids: List[str] = []

    if is_http and version != "v1.1-diminishing":
        # CR-002 (HSTS) is Not Applicable on unencrypted HTTP
        na_check_ids.append("CR-002")
        failed_check_ids.discard("CR-002")

        # Hard cap at Grade D (max score 69) for plain unencrypted HTTP
        if score > 69:
            score = 69
        if grade in ("A", "B", "C"):
            grade = "D"
            label = "Elevated Risk (Unencrypted HTTP)"

    passed_count = max(0, len(CHECK_REGISTRY) - len(na_check_ids) - len(failed_check_ids))

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "score_version": version,
        "total_deduction": total_deduction,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "category_penalties": effective_category_penalties,
        "total_checks": len(CHECK_REGISTRY),
        "passed_checks": passed_count,
        "failed_checks": len(failed_check_ids),
        "failed_check_ids": sorted(list(failed_check_ids)),
        "na_checks": len(na_check_ids),
        "na_check_ids": sorted(list(na_check_ids)),
        "is_unencrypted": is_http,
    }


def get_check_registry() -> List[Dict[str, Any]]:
    """Return the 18 security checks catalog."""
    return CHECK_REGISTRY


def get_category_summary() -> Dict[str, int]:
    """
    Return counts strictly derived from the 18 checks registry:
    Transport Security: 2, Browser & Headers: 7, Cross-Origin Security: 4, Session & Disclosure: 5.
    """
    counts: Dict[str, int] = {
        "Transport Security": 0,
        "Browser & Headers": 0,
        "Cross-Origin Security": 0,
        "Session & Disclosure": 0,
    }
    for check in CHECK_REGISTRY:
        cat = check["high_level_category"]
        counts[cat] = counts.get(cat, 0) + 1
    return counts


# Alias for compatibility
compute_posture_score = calculate_posture_score

