from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIRECTORY = PROJECT_ROOT / "data"

DATABASE_PATH = DATA_DIRECTORY / "cyberrecon.db"


def get_connection():
    """
    Create and return a SQLite database connection.
    """

    DATA_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def initialize_database():
    """
    Create all required CyberRecon database
    tables if they do not already exist.
    """

    with get_connection() as connection:

        # -------------------------------------------------
        # USERS
        # -------------------------------------------------

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                username TEXT
                    NOT NULL
                    UNIQUE
                    COLLATE NOCASE,

                email TEXT
                    NOT NULL
                    UNIQUE
                    COLLATE NOCASE,

                password_hash TEXT
                    NOT NULL,

                created_at TEXT
                    NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # -------------------------------------------------
        # SCANS
        # -------------------------------------------------

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            scan_id TEXT
                NOT NULL
                UNIQUE,

            target TEXT
                NOT NULL,

            started_at TEXT,
            duration_ms INTEGER,
            checks_performed INTEGER,
            recon_status TEXT,
            analysis_status TEXT,
            domain TEXT,
            ip_address TEXT,
            final_url TEXT,
            http_status INTEGER,
            https_enabled INTEGER,
            response_time REAL,
            redirect_count INTEGER,
            page_title TEXT,
            server TEXT,
            content_type TEXT,

            created_at TEXT
                NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
            )
            """
        )
        
        scan_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        if "user_id" not in scan_columns:

            connection.execute(
                """
                ALTER TABLE scans
                ADD COLUMN user_id INTEGER
                REFERENCES users(id)
                """
            )


        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_scans_user
            ON scans(user_id)
            """
        )


        # -------------------------------------------------
        # FINDINGS
        # -------------------------------------------------

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_database_id INTEGER
                    NOT NULL,

                finding_code TEXT,
                name TEXT,
                category TEXT,
                severity TEXT,

                confidence TEXT,
                affected_component TEXT,
                cwe TEXT,
                owasp TEXT,

                evidence TEXT,
                description TEXT,
                recommendation TEXT,

                FOREIGN KEY (
                    scan_database_id
                )
                REFERENCES scans(id)
                ON DELETE CASCADE
            )
            """
        )
        
        finding_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(findings)"
            ).fetchall()
        }


        required_finding_columns = {
            "confidence": "TEXT",
            "affected_component": "TEXT",
            "cwe": "TEXT",
            "owasp": "TEXT",
        }


        for column_name, column_type in required_finding_columns.items():

            if column_name not in finding_columns:

                connection.execute(
                    f"""
                    ALTER TABLE findings
                    ADD COLUMN {column_name} {column_type}
                    """
                )


        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_findings_scan
            ON findings (
                scan_database_id
            )
            """
        )


# =========================================================
# USER FUNCTIONS
# =========================================================


def create_user(
    username,
    email,
    password_hash,
):
    """
    Create a CyberRecon user account.
    """

    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (
                username.strip(),
                email.strip().lower(),
                password_hash,
            ),
        )

        return cursor.lastrowid


def get_user_by_username(username):
    """
    Find a user using their username.
    """

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                password_hash,
                created_at

            FROM users

            WHERE username = ?
                COLLATE NOCASE
            """,
            (
                username.strip(),
            ),
        ).fetchone()

    if row is None:
        return None

    return dict(row)


def get_user_by_email(email):
    """
    Find a user using their email address.
    """

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                password_hash,
                created_at

            FROM users

            WHERE email = ?
                COLLATE NOCASE
            """,
            (
                email.strip().lower(),
            ),
        ).fetchone()

    if row is None:
        return None

    return dict(row)


def get_user_by_id(user_id):
    """
    Find a user using their database ID.

    Password hashes are intentionally excluded
    from this function.
    """

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                created_at

            FROM users

            WHERE id = ?
            """,
            (
                user_id,
            ),
        ).fetchone()

    if row is None:
        return None

    return dict(row)


# =========================================================
# ASSESSMENT STORAGE
# =========================================================


def save_assessment(
    assessment,
    user_id,
):
    """
    Save a completed or failed CyberRecon
    assessment and its findings.
    """

    metadata = assessment.get(
        "metadata",
        {},
    )

    recon = assessment.get(
        "recon",
        {},
    )

    findings = assessment.get(
        "findings",
        [],
    )

    target = assessment.get(
        "target",
        "",
    )


    https_enabled = recon.get(
        "https_enabled"
    )

    if https_enabled is not None:
        https_enabled = int(
            bool(https_enabled)
        )


    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO scans (
                user_id,
                scan_id,
                target,
                started_at,
                duration_ms,
                checks_performed,
                recon_status,
                analysis_status,
                domain,
                ip_address,
                final_url,
                http_status,
                https_enabled,
                response_time,
                redirect_count,
                page_title,
                server,
                content_type
            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                user_id,
                metadata.get("scan_id"),
                target,
                metadata.get("started_at"),
                metadata.get("duration_ms"),
                metadata.get("checks_performed"),
                metadata.get("recon_status"),
                metadata.get("analysis_status"),
                recon.get("domain"),
                recon.get("ip_address"),
                recon.get("final_url"),
                recon.get("status_code"),
                https_enabled,
                recon.get("response_time"),
                recon.get("redirect_count"),
                recon.get("page_title"),
                recon.get("server"),
                recon.get("content_type"),
            ),
        )

        scan_database_id = (
            cursor.lastrowid
        )


        for finding in findings:

            finding_code = (
                finding.get("finding_code")
                or finding.get("id")
            )

            connection.execute(
                """
                INSERT INTO findings (
                    scan_database_id,
                    finding_code,
                    name,
                    category,
                    severity,
                    confidence,
                    affected_component,
                    cwe,
                    owasp,
                    evidence,
                    description,
                    recommendation
                )

                VALUES (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    scan_database_id,

                    finding_code,

                    finding.get(
                        "name"
                    ),

                    finding.get(
                        "category"
                    ),

                    finding.get(
                        "severity"
                    ),

                    finding.get(
                        "confidence"
                    ),

                    finding.get(
                        "affected_component"
                    ),

                    finding.get(
                        "cwe"
                    ),

                    finding.get(
                        "owasp"
                    ),

                    finding.get(
                        "evidence"
                    ),

                    finding.get(
                        "description"
                    ),

                    finding.get(
                        "recommendation"
                    ),
                ),
            )


# =========================================================
# SCAN HISTORY
# =========================================================


def get_scan_history(
    user_id,
    limit=50,
):

    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT
                scans.*,

                COUNT(findings.id)
                    AS total_findings,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'High'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS high_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'Medium'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS medium_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'Low'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS low_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'Info'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS info_count

            FROM scans

            LEFT JOIN findings
                ON findings.scan_database_id
                = scans.id

            WHERE scans.user_id = ?

            GROUP BY scans.id

            ORDER BY scans.id DESC

            LIMIT ?
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_scan_by_id(
    scan_id,
    user_id,
):

    with get_connection() as connection:

        scan = connection.execute(
            """
            SELECT *
            FROM scans

            WHERE scan_id = ?
              AND user_id = ?
            """,
            (
                scan_id,
                user_id,
            ),
        ).fetchone()


        if scan is None:
            return None


        findings = connection.execute(
            """
            SELECT
                finding_code,
                name,
                category,
                severity,
                confidence,
                affected_component,
                cwe,
                owasp,
                evidence,
                description,
                recommendation
            
            FROM findings

            WHERE scan_database_id = ?

            ORDER BY id ASC
            """,
            (
                scan["id"],
            ),
        ).fetchall()


    return {
        "scan": dict(scan),

        "findings": [
            dict(finding)
            for finding in findings
        ],
    }


def get_completed_scans(
    user_id,
    limit=100,
):

    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT
                scan_id,
                target,
                started_at,
                domain,
                analysis_status

            FROM scans

            WHERE analysis_status = 'Completed'
              AND user_id = ?

            ORDER BY id DESC

            LIMIT ?
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


# =========================================================
# DASHBOARD ANALYTICS & COMMAND CENTER AGGREGATION
# =========================================================


def get_dashboard_analytics(user_id, date_range="all", target_filter="all", severity_filter="all"):
    """
    Retrieve comprehensive, user-isolated dashboard security analytics,
    supporting cross-filtering by date_range ('24h', '7d', '30d', 'all'),
    target_filter, and severity_filter.
    """
    from cyberrecon.scanner.scoring import calculate_posture_score, CHECK_REGISTRY, CATEGORY_MAPPING

    if date_range not in ("24h", "7d", "30d", "all"):
        date_range = "all"

    with get_connection() as connection:
        # 1. Fetch available targets for this user (independent of current target filter)
        target_rows = connection.execute(
            "SELECT DISTINCT target FROM scans WHERE user_id = ? ORDER BY target ASC",
            (user_id,)
        ).fetchall()
        available_targets = [r["target"] for r in target_rows if r["target"]]

        # 2. Build where clause
        where_scans = "WHERE scans.user_id = ?"
        params = [user_id]

        if date_range == "24h":
            where_scans += " AND scans.created_at >= datetime('now', '-24 hours')"
        elif date_range == "7d":
            where_scans += " AND scans.created_at >= datetime('now', '-7 days')"
        elif date_range == "30d":
            where_scans += " AND scans.created_at >= datetime('now', '-30 days')"

        if target_filter and target_filter != "all":
            where_scans += " AND scans.target = ?"
            params.append(target_filter)

        # 3. Overview metrics
        overview = connection.execute(
            f"""
            SELECT
                COUNT(*) AS total_scans,
                COUNT(DISTINCT scans.target) AS unique_targets,
                SUM(CASE WHEN scans.recon_status = 'Completed' THEN 1 ELSE 0 END) AS successful_scans,
                SUM(CASE WHEN scans.recon_status = 'Failed' THEN 1 ELSE 0 END) AS failed_scans
            FROM scans
            {where_scans}
            """,
            params,
        ).fetchone()

        # 4. Severity metrics across all filtered scans
        severity = connection.execute(
            f"""
            SELECT
                COUNT(findings.id) AS total_findings,
                COUNT(DISTINCT findings.finding_code) AS distinct_finding_types,
                SUM(CASE WHEN findings.severity = 'High' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN findings.severity = 'Medium' THEN 1 ELSE 0 END) AS medium_count,
                SUM(CASE WHEN findings.severity = 'Low' THEN 1 ELSE 0 END) AS low_count,
                SUM(CASE WHEN findings.severity = 'Info' THEN 1 ELSE 0 END) AS info_count
            FROM scans
            LEFT JOIN findings ON findings.scan_database_id = scans.id
            {where_scans}
            """,
            params,
        ).fetchone()

        # 5. Fetch all scans in range to compute scores, timeseries & sparklines
        scans_in_range = connection.execute(
            f"""
            SELECT
                scans.id,
                scans.scan_id,
                scans.target,
                scans.started_at,
                scans.created_at,
                scans.recon_status,
                scans.analysis_status,
                scans.duration_ms
            FROM scans
            {where_scans}
            ORDER BY scans.id ASC
            """,
            params,
        ).fetchall()

        # 6. Fetch findings for all scans in range
        scan_ids = [s["id"] for s in scans_in_range]
        findings_by_scan = {s["id"]: [] for s in scans_in_range}
        if scan_ids:
            placeholders = ",".join("?" for _ in scan_ids)
            findings_rows = connection.execute(
                f"""
                SELECT
                    scan_database_id,
                    finding_code,
                    name,
                    category,
                    severity,
                    cwe,
                    owasp
                FROM findings
                WHERE scan_database_id IN ({placeholders})
                """,
                scan_ids,
            ).fetchall()
            for f in findings_rows:
                findings_by_scan[f["scan_database_id"]].append(dict(f))

        # 7. Common findings intelligence
        common_findings_raw = connection.execute(
            f"""
            SELECT
                findings.finding_code,
                findings.name,
                findings.severity,
                COUNT(DISTINCT scans.id) AS affected_assessments,
                COUNT(*) AS total_occurrences,
                MAX(scans.scan_id) AS latest_scan_id
            FROM findings
            JOIN scans ON scans.id = findings.scan_database_id
            {where_scans}
            GROUP BY findings.finding_code, findings.name, findings.severity
            ORDER BY affected_assessments DESC, total_occurrences DESC, findings.finding_code ASC
            LIMIT 5
            """,
            params,
        ).fetchall()

        # 8. Daily scan counts
        daily_rows = connection.execute(
            f"""
            SELECT
                DATE(scans.created_at) AS scan_date,
                COUNT(*) AS scan_count
            FROM scans
            {where_scans}
            GROUP BY scan_date
            ORDER BY scan_date ASC
            """,
            params,
        ).fetchall()

        # 9. Target risk row
        target_risk_row = connection.execute(
            f"""
            SELECT scans.target, COUNT(findings.id) AS finding_count
            FROM scans
            JOIN findings ON findings.scan_database_id = scans.id
            {where_scans}
            GROUP BY scans.target
            ORDER BY finding_count DESC
            LIMIT 1
            """,
            params,
        ).fetchone()

        # 10. Latest successful scan
        latest_scan_row = connection.execute(
            f"""
            SELECT scan_id, target, started_at, duration_ms
            FROM scans
            {where_scans} AND recon_status = 'Completed'
            ORDER BY id DESC
            LIMIT 1
            """,
            params,
        ).fetchone()

    overview_data = dict(overview) if overview else {}
    severity_data = dict(severity) if severity else {}

    for key in ("total_scans", "unique_targets", "successful_scans", "failed_scans"):
        overview_data[key] = overview_data.get(key) or 0

    for key in ("total_findings", "distinct_finding_types", "high_count", "medium_count", "low_count", "info_count"):
        severity_data[key] = severity_data.get(key) or 0

    total_scans = overview_data["total_scans"]
    success_rate = (
        round((overview_data["successful_scans"] / total_scans) * 100, 1)
        if total_scans
        else 0.0
    )

    # Calculate real posture scores for every scan
    scan_records = []
    scans_by_target = {}
    for s in scans_in_range:
        s_findings = findings_by_scan.get(s["id"], [])
        score_res = calculate_posture_score(s_findings)
        record = {
            "id": s["id"],
            "scan_id": s["scan_id"],
            "target": s["target"],
            "created_at": s["created_at"],
            "started_at": s["started_at"],
            "recon_status": s["recon_status"],
            "analysis_status": s["analysis_status"],
            "duration_ms": s["duration_ms"],
            "score": score_res["score"],
            "grade": score_res["grade"],
            "label": score_res["label"],
            "total_findings": len(s_findings),
            "high_count": sum(1 for f in s_findings if f["severity"] == "High"),
            "medium_count": sum(1 for f in s_findings if f["severity"] == "Medium"),
            "low_count": sum(1 for f in s_findings if f["severity"] == "Low"),
            "info_count": sum(1 for f in s_findings if f["severity"] in ("Info", "Informational")),
            "findings": s_findings,
        }
        scan_records.append(record)
        scans_by_target.setdefault(s["target"], []).append(record)

    # Determine latest scan per target to aggregate current posture & active open findings
    latest_per_target = {}
    for target, t_scans in scans_by_target.items():
        completed = [sc for sc in t_scans if sc["recon_status"] == "Completed"]
        if completed:
            latest_per_target[target] = completed[-1]

    # Compute Active Open Findings exclusively from the latest scan per target
    latest_findings_pool = []
    for t_scan in latest_per_target.values():
        latest_findings_pool.extend(t_scan.get("findings", []))

    open_high_count = sum(1 for f in latest_findings_pool if f.get("severity") == "High")
    open_med_count = sum(1 for f in latest_findings_pool if f.get("severity") == "Medium")
    open_low_count = sum(1 for f in latest_findings_pool if f.get("severity") == "Low")
    open_info_count = sum(1 for f in latest_findings_pool if f.get("severity") in ("Info", "Informational"))
    open_total_findings = len(latest_findings_pool)

    severity_data["total_findings"] = open_total_findings
    severity_data["high_count"] = open_high_count
    severity_data["medium_count"] = open_med_count
    severity_data["low_count"] = open_low_count
    severity_data["info_count"] = open_info_count
    severity_data["distinct_finding_types"] = len({f.get("finding_code") or f.get("id") for f in latest_findings_pool})

    # Current Posture Score (Average of latest scan across monitored targets)
    if latest_per_target:
        current_posture_score = int(round(sum(s["score"] for s in latest_per_target.values()) / len(latest_per_target)))
    elif scan_records:
        completed = [sc for sc in scan_records if sc["recon_status"] == "Completed"]
        current_posture_score = completed[-1]["score"] if completed else 100
    else:
        current_posture_score = 100

    # Letter grade determination
    if current_posture_score >= 90:
        current_grade = "A"
        grade_label = "Optimal Posture"
    elif current_posture_score >= 80:
        current_grade = "B"
        grade_label = "Good Posture"
    elif current_posture_score >= 70:
        current_grade = "C"
        grade_label = "Fair Posture"
    elif current_posture_score >= 60:
        current_grade = "D"
        grade_label = "Elevated Risk"
    else:
        current_grade = "F"
        grade_label = "Critical Deficiencies"

    # Posture sparkline (chronological scores)
    completed_chronological = [sc for sc in scan_records if sc["recon_status"] == "Completed"]
    if len(completed_chronological) >= 2:
        posture_sparkline = [sc["score"] for sc in completed_chronological[-12:]]
        posture_delta = completed_chronological[-1]["score"] - completed_chronological[0]["score"]
    elif len(completed_chronological) == 1:
        posture_sparkline = [completed_chronological[0]["score"]]
        posture_delta = 0
    else:
        posture_sparkline = []
        posture_delta = 0

    # Common findings list
    common_findings = []
    for idx, row in enumerate(common_findings_raw, 1):
        item = dict(row)
        item["rank"] = idx
        item["occurrence_count"] = item["total_occurrences"]
        item["affected_pct"] = (
            round((item["affected_assessments"] / total_scans) * 100, 1)
            if total_scans
            else 0.0
        )
        common_findings.append(item)

    # Activity timeline (for 7d / 30d / 24h)
    timeline = []
    days_count = 7 if date_range == "7d" else (30 if date_range == "30d" else (1 if date_range == "24h" else 14))
    daily_map = {row["scan_date"]: row["scan_count"] for row in daily_rows}
    today = datetime.now(timezone.utc).date()
    for i in range(days_count - 1, -1, -1):
        day = today - timedelta(days=i)
        iso = day.isoformat()
        count = daily_map.get(iso, 0)
        label = "Today" if i == 0 else ("Yest." if i == 1 else day.strftime("%b %d"))
        timeline.append({
            "date": iso,
            "label": label,
            "count": count,
        })
    max_activity = max([t["count"] for t in timeline] or [1])
    if max_activity == 0:
        max_activity = 1

    # Calendar Heatmap (Last 35 days grid)
    activity_calendar = []
    for i in range(34, -1, -1):
        day = today - timedelta(days=i)
        iso = day.isoformat()
        count = daily_map.get(iso, 0)
        intensity = 0 if count == 0 else (1 if count == 1 else (2 if count <= 3 else (3 if count <= 5 else 4)))
        activity_calendar.append({
            "date": iso,
            "count": count,
            "intensity": intensity,
            "weekday": day.weekday(), # 0 = Monday, 6 = Sunday
            "formatted": day.strftime("%b %d, %Y"),
        })

    # Severity Donut Breakdown (NO Critical)
    tot_findings = severity_data["total_findings"] or 1
    severity_donut = {
        "High": {"count": severity_data["high_count"], "pct": round((severity_data["high_count"] / tot_findings) * 100, 1)},
        "Medium": {"count": severity_data["medium_count"], "pct": round((severity_data["medium_count"] / tot_findings) * 100, 1)},
        "Low": {"count": severity_data["low_count"], "pct": round((severity_data["low_count"] / tot_findings) * 100, 1)},
        "Info": {"count": severity_data["info_count"], "pct": round((severity_data["info_count"] / tot_findings) * 100, 1)},
        "total": severity_data["total_findings"],
    }

    # Category Breakdown from latest scans across monitored targets
    latest_findings_pool = []
    for t_scan in latest_per_target.values():
        latest_findings_pool.extend(t_scan.get("findings", []))

    cat_checks_count = {
        "Transport Security": 2,
        "Browser & Headers": 7,
        "Cross-Origin Security": 4,
        "Session & Disclosure": 5,
    }
    cat_failing_codes = {
        "Transport Security": set(),
        "Browser & Headers": set(),
        "Cross-Origin Security": set(),
        "Session & Disclosure": set(),
    }
    for f in latest_findings_pool:
        cid = f.get("finding_code") or f.get("id")
        raw_cat = f.get("category", "")
        hl_cat = CATEGORY_MAPPING.get(raw_cat, "Browser & Headers")
        if hl_cat in cat_failing_codes and cid:
            cat_failing_codes[hl_cat].add(cid)

    category_breakdown = {}
    for cat_name, tot_cnt in cat_checks_count.items():
        f_count = len(cat_failing_codes[cat_name])
        p_count = max(0, tot_cnt - f_count)
        p_pct = int(round((p_count / tot_cnt) * 100))
        category_breakdown[cat_name] = {
            "total_checks": tot_cnt,
            "passing_checks": p_count,
            "failing_checks": f_count,
            "pass_pct": p_pct,
        }

    # Security Matrix (Targets x 18 Checks)
    check_meta_list = [
        {"id": c["id"], "name": c["name"], "category": c["high_level_category"], "severity": c["severity"]}
        for c in CHECK_REGISTRY
    ]
    matrix_targets = list(latest_per_target.keys())[:8]
    security_matrix = {}
    for t_url in matrix_targets:
        t_scan = latest_per_target[t_url]
        is_http_target = t_url.startswith("http://") or ("CR-001" in [f.get("finding_code") or f.get("id") for f in t_scan.get("findings", [])])
        f_codes = {f.get("finding_code") or f.get("id"): f for f in t_scan.get("findings", [])}
        target_cells = {}
        for c in CHECK_REGISTRY:
            cid = c["id"]
            if is_http_target and cid == "CR-002":
                target_cells[cid] = {"status": "NA", "severity": "NA", "name": c["name"]}
            elif cid in f_codes:
                target_cells[cid] = {"status": "Fail", "severity": f_codes[cid]["severity"], "name": c["name"]}
            else:
                target_cells[cid] = {"status": "Pass", "severity": "Pass", "name": c["name"]}
        security_matrix[t_url] = target_cells

    # Resolved vs New Findings (compare latest scan vs previous scan for targets)
    resolved_count = 0
    new_count = 0
    persistent_count = 0
    for target, t_scans in scans_by_target.items():
        comp = [s for s in t_scans if s["recon_status"] == "Completed"]
        if len(comp) >= 2:
            prev_codes = {f.get("finding_code") or f.get("id") for f in comp[-2]["findings"]}
            curr_codes = {f.get("finding_code") or f.get("id") for f in comp[-1]["findings"]}
            resolved_count += len(prev_codes - curr_codes)
            new_count += len(curr_codes - prev_codes)
            persistent_count += len(prev_codes & curr_codes)
        elif len(comp) == 1:
            curr_codes = {f.get("finding_code") or f.get("id") for f in comp[-1]["findings"]}
            new_count += len(curr_codes)

    # Monitored Targets Table List
    monitored_targets = []
    for t_url, t_scan in sorted(latest_per_target.items(), key=lambda kv: kv[1]["score"]):
        clean_domain = t_url.replace("https://", "").replace("http://", "").rstrip("/")
        monitored_targets.append({
            "target": t_url,
            "domain": clean_domain,
            "latest_scan_id": t_scan["scan_id"],
            "score": t_scan["score"],
            "grade": t_scan["grade"],
            "findings_count": t_scan["total_findings"],
            "high_count": t_scan["high_count"],
            "medium_count": t_scan["medium_count"],
            "last_audited": t_scan["started_at"] or t_scan["created_at"],
            "reassess_url": f"/new?target={t_url}",
        })

    # Recommended Next Actions (Computed from real findings & real scoring)
    recommended_actions = []
    remediation_titles = {
        "CR-001": "Enforce HTTPS Redirection",
        "CR-002": "Add Strict-Transport-Security (HSTS) Header",
        "CR-003": "Deploy Content Security Policy (CSP)",
        "CR-004": "Configure X-Frame-Options Header",
        "CR-005": "Enable X-Content-Type-Options: nosniff",
        "CR-006": "Strip Server Header Identity Banner",
        "CR-007": "Disable X-Powered-By Application Header",
        "CR-008": "Deploy Strict Permissions-Policy",
        "CR-009": "Set Strict-Origin-When-Cross-Origin Referrer Policy",
        "CR-010": "Configure Cache-Control on Sensitive Responses",
        "CR-011": "Remove Cleartext HTTP/2 Cleartext (h2c) Upgrades",
        "CR-012": "Restrict Wildcard CORS Access-Control-Allow-Origin",
        "CR-013": "Set Cross-Origin-Opener-Policy: same-origin",
        "CR-014": "Set Cross-Origin-Resource-Policy: same-origin",
        "CR-015": "Configure Cross-Origin-Embedder-Policy: require-corp",
        "CR-016": "Set Secure Flag on All Session Cookies",
        "CR-017": "Set HttpOnly Flag on Sensitive Cookies",
        "CR-018": "Configure SameSite=Lax or Strict Attribute",
    }
    
    seen_recommendations = set()
    for t_url, t_scan in latest_per_target.items():
        t_findings = t_scan.get("findings", [])
        cur_score = t_scan["score"]
        for f in t_findings:
            fid = f.get("finding_code") or f.get("id")
            if not fid or (t_url, fid) in seen_recommendations:
                continue
            seen_recommendations.add((t_url, fid))
            # Calculate hypothetical score without this finding
            hypo_findings = [f_other for f_other in t_findings if (f_other.get("finding_code") or f_other.get("id")) != fid]
            proj_score = calculate_posture_score(hypo_findings)["score"]
            gain = max(1, proj_score - cur_score)
            clean_dom = t_url.replace("https://", "").replace("http://", "").rstrip("/")
            action_title = f"{remediation_titles.get(fid, 'Remediate ' + f.get('name', fid))} on {clean_dom}"
            recommended_actions.append({
                "title": action_title,
                "target": t_url,
                "domain": clean_dom,
                "check_id": fid,
                "check_name": f.get("name", fid),
                "category": CATEGORY_MAPPING.get(f.get("category", ""), "Browser & Headers"),
                "severity": f.get("severity", "Medium"),
                "score_delta": gain,
                "current_score": cur_score,
                "projected_score": proj_score,
                "why_it_matters": f.get("description", "Resolves defensive security configuration gap."),
            })

    # Sort actions by highest score improvement
    recommended_actions = sorted(recommended_actions, key=lambda a: a["score_delta"], reverse=True)[:3]

    # Timeseries points for SVG Area Chart
    timeseries_points = []
    for sc in completed_chronological:
        timeseries_points.append({
            "scan_id": sc["scan_id"],
            "target": sc["target"],
            "created_at": sc["created_at"],
            "started_at": sc["started_at"],
            "score": sc["score"],
            "grade": sc["grade"],
            "findings_count": sc["total_findings"],
            "high_count": sc["high_count"],
            "medium_count": sc["medium_count"],
        })

    range_labels = {
        "all": "All Time",
        "24h": "Last 24 Hours",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
    }

    insights = {
        "top_misconfiguration": common_findings[0] if common_findings else None,
        "highest_risk_target": dict(target_risk_row) if target_risk_row else None,
        "latest_successful_scan": dict(latest_scan_row) if latest_scan_row else None,
        "distinct_finding_types": severity_data["distinct_finding_types"],
        "unique_targets": overview_data["unique_targets"],
    }

    # Recent scans formatted for reverse chronological display
    recent_scans_formatted = []
    for sc in reversed(scan_records[-10:]):
        recent_scans_formatted.append(sc)

    return {
        "overview": overview_data,
        "severity": severity_data,
        "success_rate": success_rate,
        "recent_scans": recent_scans_formatted,
        "common_findings": common_findings,
        "activity_timeline": timeline,
        "max_activity": max_activity,
        "insights": insights,
        "date_range": date_range,
        "range_label": range_labels.get(date_range, "All Time"),
        # Phase 2 Enhanced Metrics
        "posture_score": current_posture_score,
        "posture_grade": current_grade,
        "posture_label": grade_label,
        "posture_delta": posture_delta,
        "posture_sparkline": posture_sparkline,
        "timeseries_points": timeseries_points,
        "severity_donut": severity_donut,
        "category_breakdown": category_breakdown,
        "security_matrix": security_matrix,
        "matrix_checks": check_meta_list,
        "activity_calendar": activity_calendar,
        "resolved_vs_new": {
            "resolved": resolved_count,
            "new": new_count,
            "persistent": persistent_count,
        },
        "monitored_targets": monitored_targets,
        "recommended_actions": recommended_actions,
        "available_targets": available_targets,
        "filter_target": target_filter,
        "filter_severity": severity_filter,
        "is_low_data": total_scans < 2,
        "is_empty": total_scans == 0,
    }


def delete_assessment_by_id(scan_id, user_id):
    """Delete a specific assessment and its associated findings, scoped strictly to user_id."""
    with get_connection() as connection:
        scan_row = connection.execute(
            "SELECT id FROM scans WHERE scan_id = ? AND user_id = ?",
            (scan_id, user_id)
        ).fetchone()

        if not scan_row:
            return False

        scan_db_id = scan_row["id"]
        connection.execute(
            "DELETE FROM findings WHERE scan_database_id = ?",
            (scan_db_id,)
        )
        connection.execute(
            "DELETE FROM scans WHERE id = ? AND user_id = ?",
            (scan_db_id, user_id)
        )
        connection.commit()
        return True


def bulk_delete_assessments(scan_ids, user_id):
    """Delete multiple assessments and findings for a given user."""
    if not scan_ids:
        return 0

    deleted_count = 0
    with get_connection() as connection:
        for sid in scan_ids:
            scan_row = connection.execute(
                "SELECT id FROM scans WHERE scan_id = ? AND user_id = ?",
                (sid, user_id)
            ).fetchone()
            if scan_row:
                s_id = scan_row["id"]
                connection.execute("DELETE FROM findings WHERE scan_database_id = ?", (s_id,))
                connection.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (s_id, user_id))
                deleted_count += 1
        connection.commit()
    return deleted_count


def update_user_password(user_id, password_hash):
    """Update password hash for a given user."""
    with get_connection() as connection:
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id)
        )
        connection.commit()
        return True


def export_user_data(user_id):
    """Generate comprehensive JSON-serializable export of user account and assessments."""
    with get_connection() as connection:
        user_row = connection.execute(
            "SELECT id, username, email, created_at FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not user_row:
            return None

        scans_rows = get_scan_history(user_id, limit=5000)

        assessments_export = []
        for s in scans_rows:
            f_rows = connection.execute(
                "SELECT * FROM findings WHERE scan_database_id = ? ORDER BY id ASC",
                (s["id"],)
            ).fetchall()

            findings = []
            for f in f_rows:
                f_keys = f.keys()
                rec = f["recommendation"] if "recommendation" in f_keys else (f["remediation"] if "remediation" in f_keys else "")
                desc = f["description"] if "description" in f_keys else ""
                findings.append({
                    "id": f["finding_code"],
                    "finding_code": f["finding_code"],
                    "name": f["name"],
                    "category": f["category"],
                    "severity": f["severity"],
                    "description": desc,
                    "remediation": rec,
                })

            assessments_export.append({
                "scan_id": s["scan_id"],
                "target": s["target"],
                "started_at": s["started_at"],
                "created_at": s["created_at"],
                "recon_status": s["recon_status"],
                "analysis_status": s["analysis_status"],
                "total_findings": s["total_findings"],
                "high_count": s["high_count"],
                "medium_count": s["medium_count"],
                "low_count": s["low_count"],
                "info_count": s["info_count"],
                "findings": findings,
            })

        return {
            "account": {
                "id": user_row["id"],
                "username": user_row["username"],
                "email": user_row["email"],
                "created_at": user_row["created_at"],
            },
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_assessments": len(assessments_export),
            "assessments": assessments_export,
            "scans": assessments_export,
        }


def delete_user_account(user_id):
    """Delete a user account and all associated scans and findings."""
    with get_connection() as connection:
        scan_rows = connection.execute(
            "SELECT id FROM scans WHERE user_id = ?",
            (user_id,)
        ).fetchall()

        for s in scan_rows:
            connection.execute("DELETE FROM findings WHERE scan_database_id = ?", (s["id"],))

        connection.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        connection.commit()
        return True


def get_user_targets_summary(user_id):
    """Retrieve all monitored targets for a user with latest grade, sparkline, and stats."""
    from cyberrecon.scanner.scoring import calculate_posture_score

    scans_rows = get_scan_history(user_id, limit=5000)
    # Reverse so scans are chronological (oldest to newest) for sparklines
    scans_chronological = list(reversed(scans_rows))

    targets_map = {}
    for s in scans_chronological:
        tgt = s["target"]
        if not tgt:
            continue

        with get_connection() as connection:
            f_rows = connection.execute(
                "SELECT severity, category FROM findings WHERE scan_database_id = ?",
                (s["id"],)
            ).fetchall()

        findings = [{"severity": f["severity"], "category": f["category"]} for f in f_rows]
        score_data = calculate_posture_score(findings)

        if tgt not in targets_map:
            targets_map[tgt] = {
                "url": tgt,
                "domain": tgt.replace("https://", "").replace("http://", "").rstrip("/"),
                "scans": [],
                "latest_scan": None,
                "latest_score": score_data["score"],
                "latest_grade": score_data["grade"],
                "latest_label": score_data["label"],
                "open_findings": s["total_findings"],
                "high_count": s["high_count"],
                "medium_count": s["medium_count"],
                "low_count": s["low_count"],
                "info_count": s["info_count"],
                "last_scanned": s["started_at"],
            }

        targets_map[tgt]["scans"].append(score_data["score"])
        targets_map[tgt]["latest_scan"] = s["scan_id"]
        targets_map[tgt]["latest_score"] = score_data["score"]
        targets_map[tgt]["latest_grade"] = score_data["grade"]
        targets_map[tgt]["latest_label"] = score_data["label"]
        targets_map[tgt]["open_findings"] = s["total_findings"]
        targets_map[tgt]["high_count"] = s["high_count"]
        targets_map[tgt]["medium_count"] = s["medium_count"]
        targets_map[tgt]["low_count"] = s["low_count"]
        targets_map[tgt]["info_count"] = s["info_count"]
        targets_map[tgt]["last_scanned"] = s["started_at"]

    summary_list = []
    for tgt, data in targets_map.items():
        sparkline = data["scans"][-7:] if len(data["scans"]) >= 2 else [data["latest_score"], data["latest_score"]]
        data["sparkline"] = sparkline
        summary_list.append(data)

    summary_list.sort(key=lambda t: t["last_scanned"], reverse=True)
    return summary_list
