import os
import secrets
import sqlite3

from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    redirect,
    request,
    send_from_directory,
    session,
    url_for,
)

from werkzeug.security import check_password_hash, generate_password_hash

# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATABASE_PATH = BASE_DIR / "database" / "shieldsoc.db"


# =========================
# Flask Application
# =========================

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR),
    static_url_path="/static",
)
app.config.update(
    SECRET_KEY=os.environ.get(
        "SHIELDSOC_SECRET_KEY",
        secrets.token_hex(32),
    ),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

# =========================
# Database Connection
# =========================

def get_database_connection():
    """
    Opens a connection to the ShieldSOC SQLite database.
    Rows are returned as dictionary-like objects.
    """
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection

PUBLIC_ENDPOINTS = {
    "login_page",
    "api_login",
    "api_forgot_password"
    "static",
    "health_check",
}

@app.before_request
def require_authentication():

    if request.endpoint is None:
        return

    if request.endpoint in PUBLIC_ENDPOINTS:
        return

    if request.path.startswith("/static/"):
        return

    if "user_id" not in session:

        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication_required"}), 401

        return redirect(url_for("login_page"))
# ==========================
# Role-Based Access Control
# ==========================

def role_required(*allowed_roles):
    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            current_role = session.get("role")

            if current_role not in allowed_roles:
                if request.path.startswith("/api/"):
                    return jsonify(
                        {
                            "success": False,
                            "error": "forbidden",
                            "message": (
                                "You do not have permission "
                                "to perform this action."
                            ),
                        }
                    ), 403

                return redirect(url_for("dashboard"))

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator

# =========================
# Frontend Route
# =========================

@app.route("/")
def dashboard():
    return send_from_directory(FRONTEND_DIR, "index.html")


# =========================
# Dashboard Summary API
# =========================

@app.route("/api/dashboard")
def dashboard_data():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM security_logs")
    total_logs = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM security_alerts
        WHERE severity = 'Critical'
        AND status != 'Resolved'
        """
    )
    critical_alerts = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM blocked_ips")
    blocked_ips = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM incidents
        WHERE status != 'Resolved'
        """
    )
    active_incidents = cursor.fetchone()["total"]

    connection.close()

    return jsonify(
        {
            "total_logs": total_logs,
            "critical_alerts": critical_alerts,
            "blocked_ips": blocked_ips,
            "active_incidents": active_incidents,
        }
    )


# =========================
# Recent Alerts API
# =========================

@app.route("/api/alerts")
def recent_alerts():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            alert_title,
            severity,
            source,
            source_ip,
            environment,
            detected_at,
            status
        FROM security_alerts
        ORDER BY datetime(detected_at) DESC
        LIMIT 10
        """
    )

    alerts = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return jsonify(alerts)


# =========================
# Severity Distribution API
# =========================

@app.route("/api/severity")
def severity_distribution():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            severity,
            COUNT(*) AS total
        FROM security_alerts
        GROUP BY severity
        """
    )

    results = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for row in cursor.fetchall():
        results[row["severity"]] = row["total"]

    connection.close()

    return jsonify(results)


# =========================
# Suspicious IPs API
# =========================

@app.route("/api/suspicious-ips")
def suspicious_ips():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            blocked_ips.ip_address,
            blocked_ips.country,
            blocked_ips.reason,
            blocked_ips.environment,
            blocked_ips.blocked_at,
            COUNT(security_logs.id) AS event_count
        FROM blocked_ips
        LEFT JOIN security_logs
            ON blocked_ips.ip_address = security_logs.source_ip
        GROUP BY blocked_ips.ip_address
        ORDER BY event_count DESC
        LIMIT 5
        """
    )

    results = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return jsonify(results)


# =========================
# Recent Logs API
# =========================

@app.route("/api/logs")
def recent_logs():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            event_time,
            source,
            event_type,
            description,
            severity,
            source_ip,
            destination_ip,
            environment,
            status
        FROM security_logs
        ORDER BY datetime(event_time) DESC
        LIMIT 10
        """
    )

    logs = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return jsonify(logs)
@app.route("/api/logs/<int:log_id>/resolve", methods=["PUT"])
def resolve_log(log_id):
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE security_logs
        SET status = 'Resolved'
        WHERE id = ?
        """,
        (log_id,)
    )

    connection.commit()

    if cursor.rowcount == 0:
        print(f"[AUDIT] Alert #{log_id} marked as Resolved by SOC Analyst - Salma")
        connection.close()
        return jsonify({
            "success": False,
            "message": "Log not found."
        }), 404

    connection.close()

    return jsonify({
        "success": True,
        "message": "Log marked as resolved."
    })
@app.route("/api/logs/<int:log_id>/assign", methods=["PUT"])
def assign_log(log_id):
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE security_logs
        SET assigned_analyst = ?
        WHERE id = ?
        """,
        ("SOC Analyst - Salma", log_id),
    )

    connection.commit()

    if cursor.rowcount == 0:
        
        connection.close()
        return jsonify({
            "success": False,
            "message": "Log not found."
        }), 404
    print(f"[AUDIT] Alert #{log_id} assigned to SOC Analyst - Salma")
    connection.close()

    return jsonify({
        "success": True,
        "message": "Analyst assigned successfully."
    })

# =========================
# Active Incidents API
# =========================

@app.route("/api/incidents")
def active_incidents():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            incident_code,
            title,
            severity,
            environment,
            status,
            assigned_to,
            created_at
        FROM incidents
        WHERE status != 'Resolved'
        ORDER BY datetime(created_at) DESC
        LIMIT 6
        """
    )

    incidents = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return jsonify(incidents)


# =========================
# Environment Statistics API
# =========================

@app.route("/api/environments")
def environment_statistics():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            environment,
            COUNT(*) AS total_logs
        FROM security_logs
        GROUP BY environment
        ORDER BY total_logs DESC
        """
    )

    environments = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return jsonify(environments)


# =========================
# Health Check API
# =========================
@app.route("/api/dashboard")
def dashboard_statistics():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE severity='Critical'")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    blocked_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE status != 'Resolved'")
    active_incidents = cursor.fetchone()[0]

    connection.close()

    return jsonify({
        "total_logs": total_logs,
        "critical_alerts": critical_alerts,
        "blocked_ips": blocked_ips,
        "active_incidents": active_incidents
    })

@app.route("/api/health")
def health_check():
    database_exists = DATABASE_PATH.exists()

    return jsonify(
        {
            "application": "ShieldSOC",
            "status": "online" if database_exists else "database_missing",
            "database": str(DATABASE_PATH),
        }
    )


# =========================
# Run Application
# =========================

# ==========================
# Login Routes
# ==========================

@app.route("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return send_from_directory(
        FRONTEND_DIR,
        "login.html",
    )


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}

    username = str(
        data.get("username", "")
    ).strip()

    password = str(
        data.get("password", "")
    )

    if not username or not password:
        return jsonify(
            {
                "success": False,
                "message": "Username and password are required.",
            }
        ), 400

    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            full_name,
            username,
            password_hash,
            role,
            is_active
        FROM users
        WHERE username = ?
        LIMIT 1
        """,
        (username,),
    )

    user = cursor.fetchone()
    connection.close()

    valid_user = (
        user is not None
        and user["is_active"] == 1
        and check_password_hash(
            user["password_hash"],
            password,
        )
    )

    if not valid_user:
        return jsonify(
            {
                "success": False,
                "message": "Invalid username or password.",
            }
        ), 401

    session.clear()
    session.permanent = True

    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    return jsonify(
        {
            "success": True,
            "message": "Login successful.",
            "user": {
                "full_name": user["full_name"],
                "username": user["username"],
                "role": user["role"],
            },
        }
    )
@app.post("/api/forgot-password")
def api_forgot_password():
    data = request.get_json(silent=True) or {}

    username = str(
        data.get("username", "")
    ).strip().lower()

    if not username:
        return jsonify(
            {
                "success": False,
                "message": "Username is required.",
            }
        ), 400

    # لا نكشف هل الحساب موجود أم لا.
    # إرسال البريد معطل في نسخة Portfolio التجريبية.
    return jsonify(
        {
            "success": True,
            "message": (
                "If this account exists, password reset "
                "instructions have been generated."
            ),
        }
    )

@app.post("/api/logout")
def api_logout():
    session.clear()

    return jsonify(
        {
            "success": True,
            "message": "Logged out successfully.",
        }
    )


@app.get("/api/session")
def session_information():
    return jsonify(
        {
            "authenticated": True,
            "user": {
                "full_name": session.get("full_name"),
                "username": session.get("username"),
                "role": session.get("role"),
            },
        }
    )
@app.get("/api/admin/test")
@role_required("Administrator")
def admin_test():
    return jsonify(
        {
            "success": True,
            "message": "Administrator access granted.",
            "role": session.get("role"),
        }
    )
@app.get("/api/admin/users")
@role_required("Administrator")
def get_users():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            full_name,
            username,
            role,
            is_active,
            created_at
        FROM users
        ORDER BY id DESC
        """
    )

    users = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return jsonify(
        {
            "success": True,
            "users": users,
            "count": len(users),
        }
    )
@app.post("/api/admin/users")
@role_required("Administrator")
def create_user():
    data = request.get_json(silent=True) or {}

    full_name = str(data.get("full_name", "")).strip()
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    role = str(data.get("role", "Viewer")).strip()

    allowed_roles = {
        "Viewer",
        "Analyst",
        "Administrator",
    }

    if not full_name or not username or not password:
        return jsonify(
            {
                "success": False,
                "message": "Full name, username, and password are required.",
            }
        ), 400

    if role not in allowed_roles:
        return jsonify(
            {
                "success": False,
                "message": "Invalid user role.",
            }
        ), 400

    if len(username) < 3:
        return jsonify(
            {
                "success": False,
                "message": "Username must contain at least 3 characters.",
            }
        ), 400

    if len(password) < 10:
        return jsonify(
            {
                "success": False,
                "message": "Password must contain at least 10 characters.",
            }
        ), 400

    password_hash = generate_password_hash(
        password,
        method="scrypt",
    )

    connection = get_database_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO users (
                full_name,
                username,
                password_hash,
                role,
                is_active,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                full_name,
                username,
                password_hash,
                role,
                1,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

        connection.commit()
        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        connection.rollback()

        return jsonify(
            {
                "success": False,
                "message": "Username already exists.",
            }
        ), 409

    finally:
        connection.close()

    return jsonify(
        {
            "success": True,
            "message": "User created successfully.",
            "user_id": user_id,
        }
    ), 201
@app.put("/api/admin/users/<int:user_id>")
@role_required("Administrator")
def update_user(user_id):
    data = request.get_json(silent=True) or {}

    full_name = str(data.get("full_name", "")).strip()
    username = str(data.get("username", "")).strip().lower()
    role = str(data.get("role", "")).strip()
    is_active = 1 if data.get("is_active") else 0

    allowed_roles = {
        "Viewer",
        "Analyst",
        "Administrator",
    }

    if not full_name or not username or not role:
        return jsonify(
            {
                "success": False,
                "message": "Full name, username, and role are required.",
            }
        ), 400

    if role not in allowed_roles:
        return jsonify(
            {
                "success": False,
                "message": "Invalid user role.",
            }
        ), 400

    if len(username) < 3:
        return jsonify(
            {
                "success": False,
                "message": "Username must contain at least 3 characters.",
            }
        ), 400

    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, role, is_active
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    )

    user = cursor.fetchone()

    if user is None:
        connection.close()

        return jsonify(
            {
                "success": False,
                "message": "User not found.",
            }
        ), 404

    current_user_id = session.get("user_id")

    if current_user_id == user_id and is_active == 0:
        connection.close()

        return jsonify(
            {
                "success": False,
                "message": "You cannot disable your own active account.",
            }
        ), 400

    if user["role"] == "Administrator" and role != "Administrator":
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'Administrator'
            AND is_active = 1
            """
        )

        administrators_count = cursor.fetchone()["total"]

        if administrators_count <= 1:
            connection.close()

            return jsonify(
                {
                    "success": False,
                    "message": "The last administrator role cannot be changed.",
                }
            ), 400

    try:
        cursor.execute(
            """
            UPDATE users
            SET
                full_name = ?,
                username = ?,
                role = ?,
                is_active = ?
            WHERE id = ?
            """,
            (
                full_name,
                username,
                role,
                is_active,
                user_id,
            ),
        )

        connection.commit()

    except sqlite3.IntegrityError:
        connection.rollback()
        connection.close()

        return jsonify(
            {
                "success": False,
                "message": "Username already exists.",
            }
        ), 409

    connection.close()

    return jsonify(
        {
            "success": True,
            "message": "User updated successfully.",
        }
    )
@app.delete("/api/admin/users/<int:user_id>")
@role_required("Administrator")
def delete_user(user_id):
    current_user_id = session.get("user_id")

    # منع المسؤول من حذف حسابه الحالي
    if current_user_id == user_id:
        return jsonify(
            {
                "success": False,
                "message": "You cannot delete your own active account.",
            }
        ), 400

    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, username, role
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    )

    user = cursor.fetchone()

    if user is None:
        connection.close()

        return jsonify(
            {
                "success": False,
                "message": "User not found.",
            }
        ), 404

    # منع حذف آخر Administrator
    if user["role"] == "Administrator":
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'Administrator'
            AND is_active = 1
            """
        )

        administrators_count = cursor.fetchone()["total"]

        if administrators_count <= 1:
            connection.close()

            return jsonify(
                {
                    "success": False,
                    "message": "The last administrator cannot be deleted.",
                }
            ), 400

    cursor.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (user_id,),
    )

    connection.commit()
    connection.close()

    return jsonify(
        {
            "success": True,
            "message": "User deleted successfully.",
        }
    )
if __name__ == "__main__":
    app.run(debug=True)