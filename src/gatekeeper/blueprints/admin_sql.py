"""Admin blueprint for SQL query execution."""

import apsw
from flask import (
    Blueprint,
    flash,
    g,
    render_template,
    request,
    send_file,
)
from werkzeug.wrappers import Response

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.services.export import write_xlsx

bp = Blueprint("admin_sql", __name__, url_prefix="/admin/sql")


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


def _get_schema() -> list[dict[str, object]]:
    """Get database schema: table names with their column names."""
    db = get_db()
    tables: list[dict[str, object]] = []
    for (name,) in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall():
        cols = [row[1] for row in db.execute(f"PRAGMA table_info({name})").fetchall()]
        tables.append({"name": name, "columns": cols})
    return tables


@bp.route("/", methods=["GET"])
@admin_required
def index() -> str:
    """Show the SQL query page."""
    schema = _get_schema()
    return render_template("admin/sql.html", schema=schema, query="", columns=[], rows=[])


@bp.route("/", methods=["POST"])
@admin_required
def execute() -> str:
    """Execute a SQL query and display results."""
    sql = request.form.get("sql", "").strip()
    schema = _get_schema()
    columns: list[str] = []
    rows = []

    if not sql:
        flash("No SQL query provided.", "error")
        return render_template(
            "admin/sql.html", schema=schema, query=sql, columns=columns, rows=rows
        )

    try:
        cursor = get_db().cursor()
        cursor.execute(sql)
        try:
            desc = cursor.getdescription()
            columns = [d[0] for d in desc]
            rows = cursor.fetchall()
        except apsw.ExecutionCompleteError:
            flash("Statement executed successfully.", "success")
        _audit_log("sql_query", details=sql)
    except Exception as exc:
        flash(str(exc), "error")
        _audit_log("sql_query_failed", details=f"{sql} -- error: {exc}")

    return render_template("admin/sql.html", schema=schema, query=sql, columns=columns, rows=rows)


@bp.route("/export", methods=["POST"])
@admin_required
def export() -> str | Response:
    """Export SQL query results as XLSX."""
    sql = request.form.get("sql", "").strip()
    if not sql:
        flash("No SQL query provided.", "error")
        return render_template(
            "admin/sql.html", schema=_get_schema(), query=sql, columns=[], rows=[]
        )

    try:
        cursor = get_db().cursor()
        cursor.execute(sql)
        desc = cursor.getdescription()
        headers = [d[0] for d in desc]
        rows = cursor.fetchall()
    except Exception as exc:
        flash(str(exc), "error")
        return render_template(
            "admin/sql.html", schema=_get_schema(), query=sql, columns=[], rows=[]
        )

    data = [list(row) for row in rows]
    path = write_xlsx(headers, data, "query.xlsx")
    _audit_log("sql_export", details=f"{sql} -- {len(data)} rows exported")
    return send_file(path, as_attachment=True, download_name="query.xlsx")
