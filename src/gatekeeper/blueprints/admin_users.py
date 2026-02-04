"""Admin blueprint for user management."""

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.models.group import Group
from gatekeeper.models.user import User

bp = Blueprint("admin_users", __name__, url_prefix="/admin/users")

_SORTABLE_COLUMNS = {"username", "email", "fullname", "enabled", "created_at", "updated_at"}


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


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def _get_users_page(
    search: str | None,
    page: int,
    per_page: int,
    sort: str,
    order: str,
) -> tuple[list[User], int]:
    """Fetch a page of users with search, sort, and pagination.

    Returns (users, total_count).
    """
    conditions: list[str] = []
    params: list[str | int] = []

    if search:
        conditions.append("(username LIKE ? OR email LIKE ? OR fullname LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])

    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

    col = sort if sort in _SORTABLE_COLUMNS else "username"
    direction = "DESC" if order.lower() == "desc" else "ASC"

    db = get_db()

    row = db.execute(f"SELECT COUNT(*) FROM user{where}", params).fetchone()
    total = int(row[0]) if row else 0

    offset = (page - 1) * per_page
    rows = db.execute(
        f"SELECT username, email, fullname, enabled, login_salt, created_at, updated_at "
        f"FROM user{where} ORDER BY {col} {direction} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()

    users = [User._from_row(r) for r in rows]
    return users, total


@bp.route("/")
@admin_required
def list_users():
    """List users with search, sort, and pagination."""
    search = request.args.get("search", "").strip() or None
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(1, min(200, int(request.args.get("per_page", 50))))
    sort = request.args.get("sort", "username")
    order = request.args.get("order", "asc")

    users, total = _get_users_page(search, page, per_page, sort, order)
    total_pages = max(1, (total + per_page - 1) // per_page)

    # Build username -> groups mapping for the current page of users
    user_groups: dict[str, list[str]] = {}
    if users:
        db = get_db()
        usernames = [u.username for u in users]
        placeholders = ",".join("?" * len(usernames))
        rows = db.execute(
            f"SELECT username, group_name FROM group_user WHERE username IN ({placeholders}) ORDER BY group_name",
            usernames,
        ).fetchall()
        for row in rows:
            user_groups.setdefault(row[0], []).append(row[1])

    context = {
        "users": users,
        "user_groups": user_groups,
        "search": search or "",
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "sort": sort,
        "order": order,
    }

    if _is_htmx():
        return render_template("admin/users_table.html", **context)

    return render_template("admin/users.html", **context)


@bp.route("/create", methods=["GET"])
@admin_required
def create_form():
    """Show create user form."""
    return render_template("admin/user_form.html", user=None)


@bp.route("/create", methods=["POST"])
@admin_required
def create_user():
    """Create a new user."""
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    fullname = request.form.get("fullname", "").strip()
    enabled = request.form.get("enabled") == "on"

    if not username or not email:
        flash("Username and email are required.", "error")
        return redirect(url_for("admin_users.create_form"))

    if User.get(username):
        flash(f"User '{username}' already exists.", "error")
        return redirect(url_for("admin_users.create_form"))

    try:
        User.create(username=username, email=email, fullname=fullname, enabled=enabled)
        _audit_log(
            "user_created", username, f"email={email}, fullname={fullname}, enabled={enabled}"
        )
        flash(f"User '{username}' created.", "success")
    except Exception as exc:
        flash(f"Failed to create user: {exc}", "error")
        return redirect(url_for("admin_users.create_form"))

    return redirect(url_for("admin_users.list_users"))


@bp.route("/<path:username>/edit", methods=["GET"])
@admin_required
def edit_form(username: str):
    """Show edit user form."""
    user = User.get(username)
    if user is None:
        abort(404)
    return render_template("admin/user_form.html", user=user)


@bp.route("/<path:username>/edit", methods=["POST"])
@admin_required
def edit_user(username: str):
    """Update a user."""
    user = User.get(username)
    if user is None:
        abort(404)

    new_username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    fullname = request.form.get("fullname", "").strip()
    enabled = request.form.get("enabled") == "on"

    if not new_username or not email:
        flash("Username and email are required.", "error")
        return redirect(url_for("admin_users.edit_form", username=username))

    # Handle username rename
    if new_username != username:
        if User.get(new_username):
            flash(f"Username '{new_username}' is already taken.", "error")
            return redirect(url_for("admin_users.edit_form", username=username))
        user.rename(new_username)
        _audit_log("user_renamed", new_username, f"Renamed from {username}")

    user.update(email=email or None, fullname=fullname, enabled=enabled)
    _audit_log("user_updated", new_username, f"email={email}, fullname={fullname}, enabled={enabled}")
    flash(f"User '{new_username}' updated.", "success")

    return redirect(url_for("admin_users.list_users"))


@bp.route("/<path:username>/toggle", methods=["POST"])
@admin_required
def toggle_user(username: str):
    """Toggle user enabled/disabled (HTMX endpoint)."""
    user = User.get(username)
    if user is None:
        abort(404)

    new_state = not user.enabled
    user.update(enabled=new_state)
    state_label = "enabled" if new_state else "disabled"
    _audit_log("user_toggled", username, f"Set {state_label}")

    groups = Group.get_groups_for_user(username)
    return render_template("admin/user_row.html", user=user, user_groups={username: groups})


@bp.route("/<path:username>/rotate-salt", methods=["POST"])
@admin_required
def rotate_salt(username: str):
    """Rotate user's login salt, invalidating all their sessions."""
    user = User.get(username)
    if user is None:
        abort(404)

    user.rotate_login_salt()
    _audit_log("salt_rotated", username, "Login salt rotated, all sessions invalidated")
    flash(f"Login salt rotated for '{username}'. All sessions invalidated.", "success")

    return redirect(request.referrer or url_for("admin_users.list_users"))


@bp.route("/<path:username>/groups")
@admin_required
def user_groups(username: str):
    """Show user's group memberships."""
    user = User.get(username)
    if user is None:
        abort(404)

    groups = Group.get_groups_for_user(username)

    return render_template("admin/user_groups.html", user=user, groups=groups)
