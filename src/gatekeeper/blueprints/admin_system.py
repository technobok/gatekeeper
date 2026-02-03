"""Admin blueprint for system management (HTMX)."""

import shutil
import tempfile

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.models.api_key import ApiKey
from gatekeeper.models.app_setting import AppSetting
from gatekeeper.models.group import Group
from gatekeeper.models.user import User

bp = Blueprint("admin_system", __name__, url_prefix="/admin/system")


def _audit_log(action: str, target: str | None = None, details: str | None = None) -> None:
    """Write to the audit log."""
    from datetime import UTC, datetime

    db = get_db()
    now = datetime.now(UTC).isoformat()
    actor = g.user.username if hasattr(g, "user") and g.user else None
    db.execute(
        "INSERT INTO audit_log (timestamp, actor, action, target, details) VALUES (?, ?, ?, ?, ?)",
        (now, actor, action, target, details),
    )


@bp.route("/")
@admin_required
def index():
    """System dashboard with counts and recent audit entries."""
    db = get_db()

    user_count = User.count()
    group_count = Group.count()
    key_count = len(ApiKey.get_all())

    rows = db.execute(
        "SELECT id, timestamp, actor, action, target, details "
        "FROM audit_log ORDER BY id DESC LIMIT 10"
    ).fetchall()
    recent_audit = [
        {
            "id": r[0],
            "timestamp": r[1],
            "actor": r[2],
            "action": r[3],
            "target": r[4],
            "details": r[5],
        }
        for r in rows
    ]

    return render_template(
        "admin/system.html",
        user_count=user_count,
        group_count=group_count,
        key_count=key_count,
        recent_audit=recent_audit,
    )


@bp.route("/rotate-app-salt", methods=["POST"])
@admin_required
def rotate_app_salt():
    """Rotate the global app salt, invalidating all sessions."""
    AppSetting.rotate_app_salt()
    _audit_log("app_salt_rotated", details="All sessions invalidated via admin UI")

    flash("App salt rotated. All user sessions have been invalidated.", "warning")
    return redirect(url_for("admin_system.index"))


@bp.route("/backup")
@admin_required
def backup():
    """Download a copy of the SQLite database file."""
    db_path = current_app.config["DATABASE_PATH"]

    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
    tmp.close()
    shutil.copy2(db_path, tmp.name)

    _audit_log("database_backup", details="Database backup downloaded")

    return send_file(
        tmp.name,
        mimetype="application/x-sqlite3",
        as_attachment=True,
        download_name="gatekeeper_backup.sqlite3",
    )


@bp.route("/audit-log")
@admin_required
def audit_log():
    """Show paginated audit log entries."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 200)

    offset = (page - 1) * per_page
    db = get_db()

    row = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()
    total = int(row[0]) if row else 0

    rows = db.execute(
        "SELECT id, timestamp, actor, action, target, details "
        "FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()
    entries = [
        {
            "id": r[0],
            "timestamp": r[1],
            "actor": r[2],
            "action": r[3],
            "target": r[4],
            "details": r[5],
        }
        for r in rows
    ]

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "admin/audit_log.html",
        entries=entries,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
    )
