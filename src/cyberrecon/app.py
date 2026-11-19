import hmac
import os
import re
import secrets
import sqlite3

from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from cyberrecon.scanner.assessment import run_assessment
from cyberrecon.scanner.comparison import compare_assessments
from cyberrecon.scanner.security_analysis import SECURITY_CHECK_COUNT
from cyberrecon.scanner.export import (
    sanitize_export_filename,
    generate_csv_report,
    generate_pdf_report,
)
from cyberrecon.scanner.scoring import (
    CHECK_REGISTRY,
    CATEGORY_CAPS,
    GRADE_THRESHOLDS,
    SCORE_VERSION,
    SEVERITY_TIERS,
    calculate_posture_score,
    get_category_summary,
)

from cyberrecon.storage import (
    create_user,
    get_completed_scans,
    get_dashboard_analytics,
    get_scan_by_id,
    get_scan_history,
    get_user_by_email,
    get_user_by_username,
    get_user_by_id,
    initialize_database,
    save_assessment,
    delete_assessment_by_id,
    bulk_delete_assessments,
    update_user_password,
    export_user_data,
    delete_user_account,
    get_user_targets_summary,
)


# =========================================================
# APPLICATION SECURITY HELPERS
# =========================================================


def get_secret_key():
    """
    Return a stable Flask session secret.

    Production:
        CYBERRECON_SECRET_KEY=<strong random secret>

    Development:
        data/.session_secret
    """

    environment_key = os.environ.get(
        "CYBERRECON_SECRET_KEY"
    )

    if environment_key:
        return environment_key

    project_root = (
        Path(__file__).resolve().parents[2]
    )

    secret_file = (
        project_root
        / "data"
        / ".session_secret"
    )

    secret_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if secret_file.exists():
        stored_key = secret_file.read_text(
            encoding="utf-8"
        ).strip()

        if stored_key:
            try:
                secret_file.chmod(0o600)
            except OSError:
                pass

            return stored_key

    secret_key = secrets.token_hex(32)

    secret_file.write_text(
        secret_key,
        encoding="utf-8",
    )

    try:
        secret_file.chmod(0o600)
    except OSError:
        pass

    return secret_key


def login_required(view_function):
    """
    Require an authenticated CyberRecon session.
    Returns 401 JSON for /api/ endpoints and redirects to login for HTML pages.
    """

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if session.get("user_id") is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized. Please authenticate.", "status": 401}), 401

            return redirect(
                url_for(
                    "login",
                    next=request.path,
                )
            )

        return view_function(
            *args,
            **kwargs,
        )

    return wrapped_view


def is_safe_local_redirect(target):
    """
    Permit only local application redirects.
    Prevents open redirects via external URLs, protocol-relative URLs (//evil.com),
    javascript: URIs, backslashes (/\\evil.com), or control characters.
    """
    if not target or not isinstance(target, str):
        return False

    # Disallow control characters or whitespace
    if any(c in target for c in ['\r', '\n', '\t', '\0', ' ']):
        return False

    # Prevent backslash bypass (e.g. /\evil.com, /\\evil.com)
    if '\\' in target:
        return False

    # Prevent protocol-relative URLs (e.g. //evil.com)
    if target.startswith('//'):
        return False

    # Must strictly start with a single leading slash
    if not target.startswith('/'):
        return False

    try:
        parsed = urlsplit(target)
    except Exception:
        return False

    # Must have no scheme (e.g. http:, https:, javascript:, data:)
    if parsed.scheme:
        return False

    # Must have no network location / host
    if parsed.netloc:
        return False

    return True


# =========================================================
# CSRF PROTECTION
# =========================================================


def generate_csrf_token():
    """
    Return the CSRF token stored in the current session.

    A cryptographically random token is generated if
    the session does not already contain one.
    """

    token = session.get("_csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    return token


def validate_csrf_token(submitted_token):
    """
    Compare the submitted CSRF token with the token
    stored in the user's session.
    """

    stored_token = session.get(
        "_csrf_token"
    )

    if not stored_token:
        return False

    if not submitted_token:
        return False

    if not isinstance(
        submitted_token,
        str,
    ):
        return False

    try:
        return hmac.compare_digest(
            stored_token,
            submitted_token,
        )

    except TypeError:
        return False


# =========================================================
# APPLICATION FACTORY
# =========================================================


def create_app(test_config=None):

    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=get_secret_key(),

        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",

        SESSION_COOKIE_SECURE=(
            os.environ.get(
                "CYBERRECON_SECURE_COOKIES",
                "0",
            )
            == "1"
        ),

        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=8
        ),

        MAX_CONTENT_LENGTH=64 * 1024,

        # Enabled by default in the real application.
        CSRF_PROTECTION_ENABLED=True,
    )

    if test_config:
        app.config.update(
            test_config
        )

    initialize_database()


    # =====================================================
    # CSRF VALIDATION
    # =====================================================

    @app.before_request
    def protect_post_requests():
        """
        Validate all POST requests.

        This automatically protects present and future
        CyberRecon POST routes unless explicitly disabled
        in the test configuration.
        """

        if not app.config.get(
            "CSRF_PROTECTION_ENABLED",
            True,
        ):
            return None

        if request.method != "POST":
            return None

        submitted_token = (
            request.form.get(
                "csrf_token"
            )
            or request.headers.get(
                "X-CSRF-Token"
            )
        )

        if not validate_csrf_token(
            submitted_token
        ):
            return (
                "Invalid or missing CSRF token.",
                400,
            )

        return None


    # =====================================================
    # SECURITY RESPONSE HEADERS
    # =====================================================

    @app.after_request
    def apply_security_headers(response):

        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        response.headers[
            "X-Frame-Options"
        ] = "DENY"

        response.headers[
            "Referrer-Policy"
        ] = (
            "strict-origin-when-cross-origin"
        )

        response.headers[
            "Permissions-Policy"
        ] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        )

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'"
        )

        if request.endpoint != "static":

            response.headers[
                "Cache-Control"
            ] = (
                "no-store, "
                "no-cache, "
                "must-revalidate, "
                "max-age=0"
            )

            response.headers[
                "Pragma"
            ] = "no-cache"

        if (
            request.is_secure
            and os.environ.get(
                "CYBERRECON_ENABLE_HSTS",
                "0",
            )
            == "1"
        ):

            response.headers[
                "Strict-Transport-Security"
            ] = (
                "max-age=31536000; "
                "includeSubDomains"
            )

        return response


    # =====================================================
    # ERROR HANDLERS
    # =====================================================

    @app.errorhandler(404)
    def not_found(error):

        return (
            "CyberRecon resource not found.",
            404,
        )


    @app.errorhandler(413)
    def request_too_large(error):

        return (
            "Request exceeds CyberRecon's "
            "allowed size limit.",
            413,
        )


    @app.errorhandler(500)
    def internal_error(error):

        return (
            "CyberRecon encountered an "
            "internal application error.",
            500,
        )


    # =====================================================
    # TEMPLATE CONTEXT
    # =====================================================

    @app.context_processor
    def inject_global_template_values():
        def versioned_static(filename):
            file_path = os.path.join(app.static_folder, filename)
            try:
                mtime = int(os.path.getmtime(file_path))
            except Exception:
                mtime = 1
            return url_for("static", filename=filename, v=mtime)

        return {
            "current_user_id":
                session.get("user_id"),

            "current_username":
                session.get("username"),

            "csrf_token":
                generate_csrf_token(),

            "versioned_static":
                versioned_static,

            "asset_version":
                "2.5.0",
        }


    # =====================================================
    # HOME
    # =====================================================

    @app.route("/")
    def home():

        return render_template(
            "index.html",
            check_count=len(CHECK_REGISTRY),
            category_counts=get_category_summary(),
        )


    # =====================================================
    # ABOUT (Methodology, 18 Checks, Scoring, SSRF, FAQ)
    # =====================================================

    @app.route("/about")
    def about():

        return render_template(
            "about.html",
            checks=CHECK_REGISTRY,
            category_counts=get_category_summary(),
            score_version=SCORE_VERSION,
            category_caps=CATEGORY_CAPS,
            severity_tiers=SEVERITY_TIERS,
            grade_thresholds=GRADE_THRESHOLDS,
        )


    # =====================================================
    # PRIVACY POLICY & TERMS OF RESPONSIBLE USE
    # =====================================================

    @app.route("/privacy")
    def privacy():

        return render_template(
            "privacy.html"
        )


    @app.route("/terms")
    def terms():

        return render_template(
            "terms.html"
        )


    # =====================================================
    # NEW ASSESSMENT WORKSPACE
    # =====================================================

    @app.route("/new")
    @login_required
    def new_assessment():

        user_id = session.get("user_id")
        target = request.args.get("target", "").strip()

        recent_targets = []
        if user_id:
            try:
                scans = get_scan_history(user_id)
                seen = set()
                for s in scans:
                    t = s.get("target", "").strip()
                    if t and t not in seen:
                        seen.add(t)
                        recent_targets.append(t)
                        if len(recent_targets) >= 4:
                            break
            except Exception:
                pass

        return render_template(
            "new_assessment.html",
            target=target,
            recent_targets=recent_targets,
            check_count=SECURITY_CHECK_COUNT,
            error=None,
        )


    # =====================================================
    # REGISTER
    # =====================================================

    @app.route(
        "/register",
        methods=[
            "GET",
            "POST",
        ],
    )
    def register():

        if session.get("user_id"):
            return redirect(
                url_for("dashboard")
            )

        error = None
        success = None

        if request.method == "POST":

            username = (
                request.form.get(
                    "username",
                    "",
                ).strip()
            )

            email = (
                request.form.get(
                    "email",
                    "",
                )
                .strip()
                .lower()
            )

            password = request.form.get(
                "password",
                "",
            )

            confirm_password = (
                request.form.get(
                    "confirm_password",
                    "",
                )
            )

            if not username:

                error = (
                    "Username is required."
                )

            elif not re.fullmatch(
                r"[A-Za-z0-9_-]{3,30}",
                username,
            ):

                error = (
                    "Username must be 3–30 "
                    "characters and contain only "
                    "letters, numbers, underscores "
                    "or hyphens."
                )

            elif not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                email,
            ):

                error = (
                    "Enter a valid email address."
                )

            elif len(password) < 8:

                error = (
                    "Password must contain at "
                    "least 8 characters."
                )

            elif (
                password
                != confirm_password
            ):

                error = (
                    "Passwords do not match."
                )

            elif get_user_by_username(
                username
            ):

                error = (
                    "That username is already "
                    "registered."
                )

            elif get_user_by_email(
                email
            ):

                error = (
                    "That email address is "
                    "already registered."
                )

            else:

                password_hash = (
                    generate_password_hash(
                        password
                    )
                )

                try:

                    create_user(
                        username,
                        email,
                        password_hash,
                    )

                    success = (
                        "Account created successfully. "
                        "You can now log in."
                    )

                except sqlite3.IntegrityError:

                    error = (
                        "That username or email "
                        "is already registered."
                    )

        return render_template(
            "register.html",
            error=error,
            success=success,
        )


    # =====================================================
    # LOGIN
    # =====================================================

    @app.route(
        "/login",
        methods=[
            "GET",
            "POST",
        ],
    )
    def login():

        if session.get("user_id"):

            return redirect(
                url_for("dashboard")
            )

        error = None

        if request.method == "POST":

            email = (
                request.form.get(
                    "email",
                    "",
                )
                .strip()
                .lower()
            )

            password = request.form.get(
                "password",
                "",
            )

            user = get_user_by_email(
                email
            )

            if (
                user is None
                or not check_password_hash(
                    user["password_hash"],
                    password,
                )
            ):

                error = (
                    "Invalid email address "
                    "or password."
                )

            else:

                next_url = (
                    request.form.get(
                        "next"
                    )
                    or request.args.get(
                        "next"
                    )
                )

                # Clearing the session also invalidates
                # the pre-login CSRF token.
                session.clear()

                session.permanent = True

                session["user_id"] = (
                    user["id"]
                )

                session["username"] = (
                    user["username"]
                )

                # Generate a fresh authenticated-session
                # CSRF token.
                generate_csrf_token()

                if is_safe_local_redirect(
                    next_url
                ):

                    return redirect(
                        next_url
                    )

                return redirect(
                    url_for(
                        "dashboard"
                    )
                )

        return render_template(
            "login.html",
            error=error,
        )


    # =====================================================
    # LOGOUT
    # =====================================================

    @app.route(
        "/logout",
        methods=[
            "GET",
            "POST",
        ],
    )
    @login_required
    def logout():

        # GET only renders the confirmation page.
        # Session state is changed only by POST.
        # Global POST CSRF middleware validates the
        # token before this route executes.

        if request.method == "GET":

            return render_template(
                "logout.html"
            )

        session.clear()

        return redirect(
            url_for("home")
        )


    # =====================================================
    # RUN ASSESSMENT
    # =====================================================

    @app.route(
        "/scan",
        methods=[
            "GET",
            "POST",
        ],
    )
    def scan():

        # Gracefully handle GET requests to prevent 405 Method Not Allowed
        if request.method == "GET":
            if session.get("user_id"):
                return redirect(
                    url_for(
                        "new_assessment"
                    )
                )
            return redirect(
                url_for(
                    "login",
                    next=url_for(
                        "new_assessment"
                    ),
                )
            )

        target = (
            request.form.get(
                "target",
                "",
            )
            .strip()
        )

        # Preserve intended target safely across authentication flow
        if session.get("user_id") is None:
            if target:
                return redirect(
                    url_for(
                        "login",
                        next=url_for(
                            "new_assessment",
                            target=target,
                        ),
                    )
                )
            return redirect(
                url_for(
                    "login",
                    next=url_for(
                        "new_assessment"
                    ),
                )
            )

        try:

            assessment = run_assessment(
                target
            )

            save_assessment(
                assessment,
                session["user_id"],
            )

            # Render results template with saved assessment
            return render_template(
                "results.html",
                assessment=assessment,
                **assessment,
            )

        except ValueError as error:

            recent_targets = []
            try:
                scans = get_scan_history(
                    session["user_id"]
                )
                seen = set()
                for s in scans:
                    t = (
                        s.get("target", "")
                        .strip()
                    )
                    if t and t not in seen:
                        seen.add(t)
                        recent_targets.append(t)
                        if len(recent_targets) >= 4:
                            break
            except Exception:
                pass

            return render_template(
                "new_assessment.html",
                error=str(error),
                target=target,
                recent_targets=recent_targets,
                check_count=SECURITY_CHECK_COUNT,
            )


    # =====================================================
    # DASHBOARD
    # =====================================================

    @app.route("/dashboard")
    @login_required
    def dashboard():

        date_range = request.args.get("range", "all").strip().lower()
        if date_range not in ("24h", "7d", "30d", "all"):
            date_range = "all"

        target_filter = request.args.get("target", "all").strip()
        severity_filter = request.args.get("severity", "all").strip()

        analytics = (
            get_dashboard_analytics(
                session["user_id"],
                date_range=date_range,
                target_filter=target_filter,
                severity_filter=severity_filter,
            )
        )

        return render_template(
            "dashboard.html",
            analytics=analytics,
            active_range=date_range,
            target_filter=target_filter,
            severity_filter=severity_filter,
        )


    # =====================================================
    # DASHBOARD REST APIS (CROSS-FILTERING & ASYNC DATA)
    # =====================================================

    @app.route("/api/dashboard/summary")
    @login_required
    def api_dashboard_summary():
        user_id = session.get("user_id")
        date_range = request.args.get("range", "all").strip().lower()
        target_filter = request.args.get("target", "all").strip()
        severity_filter = request.args.get("severity", "all").strip()

        valid_ranges = {"24h", "7d", "30d", "all"}
        valid_severities = {"all", "High", "Medium", "Low", "Info"}

        if date_range not in valid_ranges:
            return jsonify({"error": "Invalid date range parameter", "valid": list(valid_ranges)}), 400

        if severity_filter not in valid_severities:
            return jsonify({"error": "Invalid severity filter parameter", "valid": list(valid_severities)}), 400

        if len(target_filter) > 255 or any(c in target_filter for c in ("\r", "\n", "<", ">", '"', "'", "\\")):
            return jsonify({"error": "Invalid target filter parameter"}), 400

        data = get_dashboard_analytics(
            user_id,
            date_range=date_range,
            target_filter=target_filter,
            severity_filter=severity_filter,
        )
        return jsonify(data)


    @app.route("/api/dashboard/timeseries")
    @login_required
    def api_dashboard_timeseries():
        user_id = session.get("user_id")
        date_range = request.args.get("range", "all").strip().lower()
        target_filter = request.args.get("target", "all").strip()

        valid_ranges = {"24h", "7d", "30d", "all"}
        if date_range not in valid_ranges:
            return jsonify({"error": "Invalid date range parameter", "valid": list(valid_ranges)}), 400

        if len(target_filter) > 255 or any(c in target_filter for c in ("\r", "\n", "<", ">", '"', "'", "\\")):
            return jsonify({"error": "Invalid target filter parameter"}), 400

        data = get_dashboard_analytics(
            user_id,
            date_range=date_range,
            target_filter=target_filter,
        )
        return jsonify({
            "timeseries": data.get("timeseries_points", []),
            "date_range": date_range,
            "target": target_filter,
        })


    @app.route("/api/dashboard/matrix")
    @login_required
    def api_dashboard_matrix():
        user_id = session.get("user_id")
        target_filter = request.args.get("target", "all").strip()

        if len(target_filter) > 255 or any(c in target_filter for c in ("\r", "\n", "<", ">", '"', "'", "\\")):
            return jsonify({"error": "Invalid target filter parameter"}), 400

        data = get_dashboard_analytics(
            user_id,
            target_filter=target_filter,
        )
        return jsonify({
            "checks": data.get("matrix_checks", []),
            "matrix": data.get("security_matrix", {}),
        })



    # =====================================================
    # HISTORY
    # =====================================================

    @app.route("/history")
    @login_required
    def history():

        scans = get_scan_history(
            session["user_id"]
        )

        return render_template(
            "history.html",
            scans=scans,
        )


    # =====================================================
    # CANONICAL ASSESSMENT REPORT & ARCHIVE
    # =====================================================

    @app.route("/assessments/<scan_id>")
    @app.route("/history/<scan_id>")
    @login_required
    def scan_detail(scan_id):
        user_id = session["user_id"]
        stored_assessment = get_scan_by_id(scan_id, user_id)

        if stored_assessment is None:
            return render_template("404.html", resource="Assessment"), 404

        # When a browser navigates to legacy /history/<id>, redirect 301 to canonical /assessments/<id>
        if request.path.startswith("/history/") and (
            request.headers.get("Sec-Fetch-Mode") == "navigate"
            or request.args.get("legacy_redirect") == "1"
        ):
            return redirect(f"/assessments/{scan_id}", 301)

        scan_record = stored_assessment["scan"]
        findings = stored_assessment["findings"]
        posture_data = calculate_posture_score(findings)

        # Categorize findings into 4 high-level categories
        cat_map = {
            "Transport Security": "Transport Security",
            "Browser Security": "Browser & Headers",
            "Privacy and Browser Security": "Browser & Headers",
            "Cross-Origin Security": "Cross-Origin Security",
            "Information Disclosure": "Session & Disclosure",
            "Session Security": "Session & Disclosure",
        }

        grouped_findings = {
            "Transport Security": [],
            "Browser & Headers": [],
            "Cross-Origin Security": [],
            "Session & Disclosure": [],
        }

        for f in findings:
            raw_cat = f.get("category", "")
            hl_cat = cat_map.get(raw_cat, "Browser & Headers")
            if hl_cat in grouped_findings:
                grouped_findings[hl_cat].append(f)

        # Build list of passed checks
        failed_ids = set(posture_data.get("failed_check_ids", []))
        passed_checks = [c for c in CHECK_REGISTRY if c["id"] not in failed_ids]

        # Fetch previous scan of the same target for quick compare
        all_target_scans = [
            s for s in get_completed_scans(user_id)
            if s["target"] == scan_record["target"] and s["scan_id"] != scan_id
        ]
        previous_scan = all_target_scans[0] if all_target_scans else None

        return render_template(
            "scan_detail.html",
            scan=scan_record,
            findings=findings,
            posture_data=posture_data,
            grouped_findings=grouped_findings,
            passed_checks=passed_checks,
            previous_scan=previous_scan,
            score_version=SCORE_VERSION,
        )


    # Canonical alias and redirect for old /scan/<id> and /canonical_assessment_report/<id>
    @app.route("/canonical_assessment_report/<scan_id>")
    @app.route("/scan/<scan_id>")
    @login_required
    def legacy_scan_detail_redirect(scan_id):
        """Redirect legacy scan URLs to canonical /assessments/<scan_id>."""
        return redirect(f"/assessments/{scan_id}", 301)


    @app.route("/assessments/<scan_id>/delete", methods=["POST"])
    @login_required
    def delete_assessment_route(scan_id):
        """Delete an individual assessment with CSRF protection."""
        user_id = session["user_id"]
        delete_assessment_by_id(scan_id, user_id)
        return redirect(url_for("history"))


    @app.route("/assessments/<scan_id>/export.json")
    @login_required
    def export_assessment_json(scan_id):
        """Download complete assessment details as structured JSON."""
        user_id = session["user_id"]
        stored_assessment = get_scan_by_id(scan_id, user_id)
        if not stored_assessment:
            return render_template("404.html", resource="Assessment"), 404

        findings = stored_assessment["findings"]
        posture_data = calculate_posture_score(findings)
        scan = stored_assessment["scan"]

        payload = {
            "scan_id": scan_id,
            "target": scan.get("target"),
            "metadata": scan,
            "posture": posture_data,
            "findings": findings,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
        res = jsonify(payload)
        filename = sanitize_export_filename(
            scan.get("target", ""),
            scan_id,
            scan.get("timestamp") or scan.get("started_at", ""),
            "json",
        )
        res.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        res.headers["Content-Type"] = "application/json"
        return res

    @app.route("/assessments/<scan_id>/export.pdf")
    @login_required
    def export_assessment_pdf(scan_id):
        """Download assessment report as native PDF."""
        user_id = session["user_id"]
        stored_assessment = get_scan_by_id(scan_id, user_id)
        if not stored_assessment:
            return render_template("404.html", resource="Assessment"), 404

        scan = stored_assessment["scan"]
        findings = stored_assessment["findings"]
        posture_data = calculate_posture_score(findings)

        pdf_bytes = generate_pdf_report(scan, findings, posture_data)
        res = make_response(pdf_bytes)
        filename = sanitize_export_filename(
            scan.get("target", ""),
            scan_id,
            scan.get("timestamp") or scan.get("started_at", ""),
            "pdf",
        )
        res.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        res.headers["Content-Type"] = "application/pdf"
        return res

    @app.route("/assessments/<scan_id>/export.csv")
    @login_required
    def export_assessment_csv(scan_id):
        """Download assessment findings as CSV with formula injection defense."""
        user_id = session["user_id"]
        stored_assessment = get_scan_by_id(scan_id, user_id)
        if not stored_assessment:
            return render_template("404.html", resource="Assessment"), 404

        scan = stored_assessment["scan"]
        findings = stored_assessment["findings"]
        posture_data = calculate_posture_score(findings)

        csv_text = generate_csv_report(scan, findings, posture_data)
        res = make_response(csv_text)
        filename = sanitize_export_filename(
            scan.get("target", ""),
            scan_id,
            scan.get("timestamp") or scan.get("started_at", ""),
            "csv",
        )
        res.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        res.headers["Content-Type"] = "text/csv; charset=utf-8"
        return res

    @app.route("/history/<scan_id>/report")
    @app.route("/assessments/<scan_id>/report")
    @app.route("/assessments/<scan_id>/export.html")
    @login_required
    def assessment_report(scan_id):
        """Download standalone HTML assessment report."""
        user_id = session["user_id"]
        stored_assessment = get_scan_by_id(scan_id, user_id)
        if stored_assessment is None:
            return render_template("404.html", resource="Report"), 404

        scan_data = stored_assessment["scan"]
        findings = stored_assessment["findings"]
        severity_summary = {
            "High": sum(1 for f in findings if f.get("severity") == "High"),
            "Medium": sum(1 for f in findings if f.get("severity") == "Medium"),
            "Low": sum(1 for f in findings if f.get("severity") == "Low"),
            "Info": sum(1 for f in findings if f.get("severity") == "Info"),
            "Total": len(findings),
        }

        rendered_report = render_template(
            "report.html",
            scan=scan_data,
            findings=findings,
            severity_summary=severity_summary,
        )

        response = make_response(rendered_report)
        filename = sanitize_export_filename(
            scan_data.get("target", ""),
            scan_id,
            scan_data.get("timestamp") or scan_data.get("started_at", ""),
            "html",
        )
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        return response


    # =====================================================
    # TARGETS DIRECTORY (/targets)
    # =====================================================

    @app.route("/targets")
    @login_required
    def targets_list():
        user_id = session["user_id"]
        targets = get_user_targets_summary(user_id)
        return render_template("targets.html", targets=targets)


    # =====================================================
    # SETTINGS (/settings)
    # =====================================================

    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings_view():
        user_id = session["user_id"]
        user = get_user_by_id(user_id)
        pw_error = None
        pw_success = None
        active_tab = request.args.get("tab", "profile")

        if request.method == "POST":
            action = request.form.get("action", "change_password")
            if action == "change_password":
                active_tab = "password"
                current_pw = request.form.get("current_password", "")
                new_pw = request.form.get("new_password", "")
                confirm_pw = request.form.get("confirm_password", "")

                user_creds = get_user_by_email(user["email"])
                if not user_creds or not check_password_hash(user_creds["password_hash"], current_pw):
                    pw_error = "Current password is incorrect."
                elif len(new_pw) < 8:
                    pw_error = "New password must be at least 8 characters long."
                elif new_pw != confirm_pw:
                    pw_error = "New passwords do not match."
                else:
                    update_user_password(user["id"], generate_password_hash(new_pw))
                    pw_success = "Password successfully changed."

        return render_template(
            "settings.html",
            user=user,
            pw_error=pw_error,
            pw_success=pw_success,
            active_tab=active_tab,
        )


    @app.route("/settings/export")
    @login_required
    def settings_export_archive():
        data = export_user_data(session["user_id"])
        if not data:
            return jsonify({"error": "User not found"}), 404
        res = jsonify(data)
        res.headers["Content-Disposition"] = 'attachment; filename="CyberRecon_DataExport.json"'
        return res


    @app.route("/settings/delete-account", methods=["POST"])
    @login_required
    def settings_delete_account_action():
        user = get_user_by_id(session["user_id"])
        pw = request.form.get("password", "")
        if not check_password_hash(user["password_hash"], pw):
            return render_template(
                "settings.html",
                user=user,
                account_delete_error="Incorrect password. Account deletion aborted.",
                active_tab="data",
            )
        delete_user_account(user["id"])
        session.clear()
        return redirect(url_for("home"))


    @app.route("/history/bulk-delete", methods=["POST"])
    @login_required
    def history_bulk_delete_action():
        scan_ids = request.form.getlist("scan_ids")
        if scan_ids:
            bulk_delete_assessments(scan_ids, session["user_id"])
        return redirect(url_for("history"))


    # =====================================================
    # HISTORICAL COMPARISON (/compare)
    # =====================================================

    @app.route("/compare")
    @login_required
    def compare_scans():
        user_id = session["user_id"]
        scans = get_completed_scans(user_id)

        target_filter = request.args.get("target")
        baseline_id = request.args.get("baseline") or request.args.get("scan_a")
        current_id = request.args.get("current") or request.args.get("scan_b")

        # Group available scans by target
        scans_by_target = {}
        for s in scans:
            tgt = s["target"]
            if tgt not in scans_by_target:
                scans_by_target[tgt] = []
            scans_by_target[tgt].append(s)

        # Preselect target if query passed
        if not target_filter and baseline_id:
            b_scan = get_scan_by_id(baseline_id, user_id)
            if b_scan:
                target_filter = b_scan["scan"]["target"]

        # Default to first target with 2+ scans if no target passed
        if not target_filter:
            for tgt, t_scans in scans_by_target.items():
                if len(t_scans) >= 2:
                    target_filter = tgt
                    break

        available_target_scans = scans_by_target.get(target_filter, []) if target_filter else []

        # Auto-prefill latest 2 scans if baseline/current not explicitly set
        if target_filter and len(available_target_scans) >= 2 and not (baseline_id and current_id):
            current_id = available_target_scans[0]["scan_id"]
            baseline_id = available_target_scans[1]["scan_id"]

        comparison = None
        comparison_error = None
        transition_matrix = []
        baseline_score = None
        current_score = None
        score_delta = 0

        if baseline_id and current_id:
            baseline_assessment = get_scan_by_id(baseline_id, user_id)
            current_assessment = get_scan_by_id(current_id, user_id)

            if baseline_assessment is None or current_assessment is None:
                comparison_error = "One or both stored assessments could not be found."
            elif baseline_id == current_id:
                comparison_error = "Please select two different assessments to compare."
            else:
                try:
                    comparison = compare_assessments(baseline_assessment, current_assessment)
                    
                    # Compute scores & transition matrix
                    baseline_score = calculate_posture_score(baseline_assessment["findings"])
                    current_score = calculate_posture_score(current_assessment["findings"])
                    score_delta = current_score["score"] - baseline_score["score"]

                    b_find_map = {f["finding_code"]: f for f in baseline_assessment["findings"]}
                    c_find_map = {f["finding_code"]: f for f in current_assessment["findings"]}

                    for chk in CHECK_REGISTRY:
                        cid = chk["id"]
                        was_fail = cid in b_find_map
                        is_fail = cid in c_find_map

                        if was_fail and not is_fail:
                            st = "Resolved"
                            bdg = "badge-pass"
                        elif not was_fail and is_fail:
                            st = "New"
                            bdg = "badge-high"
                        elif was_fail and is_fail:
                            st = "Persistent"
                            bdg = "badge-medium"
                        else:
                            st = "Pass"
                            bdg = "badge-subtle"

                        transition_matrix.append({
                            "id": chk["id"],
                            "name": chk["name"],
                            "category": chk["high_level_category"],
                            "severity": chk["severity"],
                            "status": st,
                            "badge": bdg,
                            "baseline_status": "Fail" if was_fail else "Pass",
                            "current_status": "Fail" if is_fail else "Pass",
                        })

                except ValueError as error:
                    comparison_error = str(error)

        return render_template(
            "compare.html",
            scans=scans,
            scans_by_target=scans_by_target,
            target_filter=target_filter,
            target_scans=available_target_scans,
            comparison=comparison,
            comparison_error=comparison_error,
            selected_baseline=baseline_id,
            selected_current=current_id,
            baseline_score=baseline_score,
            current_score=current_score,
            score_delta=score_delta,
            transition_matrix=transition_matrix,
        )


    # =====================================================
    # BRANDED ERROR HANDLERS
    # =====================================================

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template("404.html"), 404


    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template("500.html"), 500


    return app