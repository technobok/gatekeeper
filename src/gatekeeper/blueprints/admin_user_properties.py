"""Admin blueprint for user property type management."""

from datetime import UTC, datetime

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.wrappers import Response

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.services.export import write_xlsx

bp = Blueprint("admin_user_properties", __name__, url_prefix="/admin/user-properties")


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def _audit_log(action: str, target: str | None = None, details: str | None = None) -> None:
    """Write to the audit log."""
    db = get_db()
    now = datetime.now(UTC).isoformat()
    actor = g.user.username if hasattr(g, "user") and g.user else None
    db.execute(
        "INSERT INTO audit_log (timestamp, actor, action, target, details) VALUES (?, ?, ?, ?, ?)",
        (now, actor, action, target, details),
    )


def _property_types_with_counts() -> list[dict]:
    """Get all distinct (app, key) pairs with user counts."""
    db = get_db()
    rows = db.execute(
        "SELECT app, key, COUNT(DISTINCT username) AS user_count "
        "FROM user_property "
        "GROUP BY app, key "
        "ORDER BY app, key"
    ).fetchall()
    return [{"app": row[0], "key": row[1], "user_count": row[2]} for row in rows]


@bp.route("/")
@admin_required
def list_properties() -> str:
    """List all property types with user counts."""
    property_types = _property_types_with_counts()
    if _is_htmx():
        return render_template("admin/user_properties_table.html", property_types=property_types)
    return render_template("admin/user_properties.html", property_types=property_types)


@bp.route("/export")
@admin_required
def export() -> Response:
    """Export all property types as XLSX."""
    property_types = _property_types_with_counts()
    headers = ["App", "Key", "Users"]
    data = [[pt["app"], pt["key"], pt["user_count"]] for pt in property_types]
    path = write_xlsx(headers, data, "user_properties.xlsx")
    _audit_log("user_properties_exported", details=f"{len(data)} property types exported")
    return send_file(path, as_attachment=True, download_name="user_properties.xlsx")


@bp.route("/create", methods=["GET"])
@admin_required
def create_form() -> str:
    """Show create property form."""
    return render_template("admin/user_property_form.html", property_type=None)


@bp.route("/create", methods=["POST"])
@admin_required
def create_property() -> Response:
    """Create a new user property."""
    app_name = request.form.get("app", "").strip()
    key = request.form.get("key", "").strip()
    username = request.form.get("username", "").strip()
    value = request.form.get("value", "").strip()

    if not app_name or not key:
        flash("App and Key are required.", "error")
        return redirect(url_for("admin_user_properties.create_form"))

    if username:
        from gatekeeper.models.user import User

        if User.get(username) is None:
            flash(f"User '{username}' not found.", "error")
            return redirect(url_for("admin_user_properties.create_form"))

        from gatekeeper.models.user_property import UserProperty

        UserProperty.set(username, app_name, key, value or None)
        _audit_log(
            "user_property_created",
            f"{app_name}/{key}",
            f"username={username}, value={value}",
        )
        flash(f"Property '{app_name}/{key}' set for user '{username}'.", "success")
    else:
        flash("Property type noted. Add a username and value to create an actual property.", "info")
        return redirect(url_for("admin_user_properties.create_form"))

    return redirect(url_for("admin_user_properties.list_properties"))


@bp.route("/<app>/<key>/edit", methods=["GET"])
@admin_required
def edit_form(app: str, key: str) -> str:
    """Show edit form for a property type."""
    db = get_db()
    row = db.execute(
        "SELECT COUNT(DISTINCT username) FROM user_property WHERE app = ? AND key = ?",
        (app, key),
    ).fetchone()
    if not row or row[0] == 0:
        abort(404)
    assert row is not None
    property_type = {"app": app, "key": key, "user_count": row[0]}
    return render_template("admin/user_property_form.html", property_type=property_type)


@bp.route("/<app>/<key>/edit", methods=["POST"])
@admin_required
def edit_property(app: str, key: str) -> Response:
    """Rename a property type (update app/key for all users)."""
    new_app = request.form.get("app", "").strip()
    new_key = request.form.get("key", "").strip()

    if not new_app or not new_key:
        flash("App and Key are required.", "error")
        return redirect(url_for("admin_user_properties.edit_form", app=app, key=key))

    if new_app == app and new_key == key:
        flash("No changes made.", "info")
        return redirect(url_for("admin_user_properties.list_properties"))

    db = get_db()
    db.execute(
        "UPDATE user_property SET app = ?, key = ? WHERE app = ? AND key = ?",
        (new_app, new_key, app, key),
    )
    _audit_log(
        "user_property_type_renamed",
        f"{app}/{key}",
        f"Renamed to {new_app}/{new_key}",
    )
    flash(f"Property type renamed from '{app}/{key}' to '{new_app}/{new_key}'.", "success")
    return redirect(url_for("admin_user_properties.list_properties"))


@bp.route("/<app>/<key>/delete", methods=["POST"])
@admin_required
def delete_property(app: str, key: str) -> str | Response:
    """Delete all instances of a property type."""
    db = get_db()
    db.execute(
        "DELETE FROM user_property WHERE app = ? AND key = ?",
        (app, key),
    )
    _audit_log("user_property_type_deleted", f"{app}/{key}")
    flash(f"Property type '{app}/{key}' deleted.", "success")
    if _is_htmx():
        property_types = _property_types_with_counts()
        return render_template("admin/user_properties_table.html", property_types=property_types)
    return redirect(url_for("admin_user_properties.list_properties"))


@bp.route("/<app>/<key>/users")
@admin_required
def users(app: str, key: str) -> str:
    """Show users who have this property."""
    db = get_db()
    rows = db.execute(
        "SELECT username, value FROM user_property WHERE app = ? AND key = ? ORDER BY username",
        (app, key),
    ).fetchall()
    if not rows:
        abort(404)
    user_values = [{"username": r[0], "value": r[1]} for r in rows]
    return render_template(
        "admin/user_property_users.html", app=app, key=key, user_values=user_values
    )


@bp.route("/<app>/<key>/users/<path:username>/remove", methods=["POST"])
@admin_required
def remove_user(app: str, key: str, username: str) -> str | Response:
    """Remove a property from a specific user."""
    from gatekeeper.models.user_property import UserProperty

    deleted = UserProperty.delete(username, app, key)
    if deleted:
        _audit_log("user_property_removed", f"{app}/{key}/{username}")
        flash(f"Removed property '{app}/{key}' from user '{username}'.", "success")
    else:
        flash(f"Property not found for user '{username}'.", "error")

    if _is_htmx():
        db = get_db()
        rows = db.execute(
            "SELECT username, value FROM user_property WHERE app = ? AND key = ? ORDER BY username",
            (app, key),
        ).fetchall()
        user_values = [{"username": r[0], "value": r[1]} for r in rows]
        return render_template(
            "admin/user_property_users_list.html",
            app=app,
            key=key,
            user_values=user_values,
        )
    return redirect(url_for("admin_user_properties.users", app=app, key=key))
