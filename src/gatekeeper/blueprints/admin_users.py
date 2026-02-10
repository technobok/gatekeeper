"""Admin blueprint for user management."""

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.models.group import Group
from gatekeeper.models.user import User
from gatekeeper.services.export import write_xlsx

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
            user_groups.setdefault(str(row[0]), []).append(str(row[1]))

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


@bp.route("/export")
@admin_required
def export():
    """Export all users as XLSX."""
    db = get_db()
    rows = db.execute(
        "SELECT username, email, fullname, enabled, created_at, updated_at FROM user ORDER BY username"
    ).fetchall()

    # Build username -> groups mapping
    all_groups: dict[str, list[str]] = {}
    group_rows = db.execute(
        "SELECT username, group_name FROM group_user ORDER BY group_name"
    ).fetchall()
    for gr in group_rows:
        all_groups.setdefault(str(gr[0]), []).append(str(gr[1]))

    headers = ["Username", "Email", "Full Name", "Groups", "Enabled", "Created", "Updated"]
    data = [
        [
            r[0],
            r[1],
            r[2],
            ", ".join(all_groups.get(str(r[0]), [])),
            "Yes" if r[3] else "No",
            r[4],
            r[5],
        ]
        for r in rows
    ]

    path = write_xlsx(headers, data, "users.xlsx")
    _audit_log("users_exported", details=f"{len(data)} users exported")
    return send_file(path, as_attachment=True, download_name="users.xlsx")


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
        standard = Group.get("standard")
        if standard:
            standard.add_member(username)
        _audit_log(
            "user_created", username, f"email={email}, fullname={fullname}, enabled={enabled}"
        )
        flash(f"User '{username}' created.", "success")
    except Exception as exc:
        flash(f"Failed to create user: {exc}", "error")
        return redirect(url_for("admin_users.create_form"))

    return redirect(url_for("admin_users.list_users"))


@bp.route("/ldap-provision", methods=["GET"])
@admin_required
def ldap_provision_form():
    """Show LDAP user provisioning form."""
    from gatekeeper.services.ldap_service import is_ldap_enabled

    if not is_ldap_enabled():
        flash("LDAP is not enabled in configuration.", "error")
        return redirect(url_for("admin_users.list_users"))

    return render_template("admin/user_ldap_provision.html")


@bp.route("/ldap-provision", methods=["POST"])
@admin_required
def ldap_provision():
    """Provision a user from LDAP."""
    from flask import current_app

    from gatekeeper.services.ldap_service import (
        is_ldap_enabled,
        lookup_by_email,
        lookup_by_username,
    )

    if not is_ldap_enabled():
        flash("LDAP is not enabled in configuration.", "error")
        return redirect(url_for("admin_users.list_users"))

    identifier = request.form.get("identifier", "").strip()
    if not identifier:
        flash("Please enter an email, username, or domain\\username.", "error")
        return redirect(url_for("admin_users.ldap_provision_form"))

    ldap_user = None
    lookup_type = ""

    if "@" in identifier:
        # Email lookup
        lookup_type = "email"
        ldap_user = lookup_by_email(identifier)
    elif "\\" in identifier:
        # domain\username format
        lookup_type = "domain\\username"
        parts = identifier.split("\\", 1)
        domain = parts[0].upper()
        username = parts[1]
        ldap_user = lookup_by_username(domain, username)
    else:
        # Bare username - try all configured domains
        lookup_type = "username"
        domains = current_app.config.get("LDAP_DOMAINS", [])
        current_app.logger.debug(
            f"LDAP provision: searching bare username '{identifier}' across domains: {domains}"
        )
        for domain in domains:
            ldap_user = lookup_by_username(domain, identifier)
            if ldap_user:
                break

    if not ldap_user:
        flash(f"No user found in LDAP for '{identifier}' (searched by {lookup_type}).", "error")
        return redirect(url_for("admin_users.ldap_provision_form"))

    # Check if user already exists
    existing = User.get(ldap_user.username)
    if existing:
        flash(
            f"User '{ldap_user.username}' already exists (email: {existing.email}).",
            "error",
        )
        return redirect(url_for("admin_users.ldap_provision_form"))

    # Create the user
    User.create(
        username=ldap_user.username,
        email=ldap_user.email,
        fullname=ldap_user.fullname,
        enabled=True,
    )

    # Add to standard group
    standard = Group.get("standard")
    if standard:
        standard.add_member(ldap_user.username)

    _audit_log(
        "user_ldap_provisioned",
        ldap_user.username,
        f"email={ldap_user.email}, fullname={ldap_user.fullname}",
    )
    flash(
        f"User '{ldap_user.username}' provisioned from LDAP "
        f"(email: {ldap_user.email}, name: {ldap_user.fullname}).",
        "success",
    )

    return redirect(url_for("admin_users.list_users"))


@bp.route("/<path:username>/edit", methods=["GET"])
@admin_required
def edit_form(username: str):
    """Show edit user form."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)
    groups = Group.get_groups_for_user(username)
    db = get_db()
    prop_rows = db.execute(
        "SELECT app, key, value FROM user_property WHERE LOWER(username) = ? ORDER BY app, key",
        (username,),
    ).fetchall()
    properties = [{"app": r[0], "key": r[1], "value": r[2]} for r in prop_rows]
    return render_template("admin/user_form.html", user=user, groups=groups, properties=properties)


@bp.route("/<path:username>/edit", methods=["POST"])
@admin_required
def edit_user(username: str):
    """Update a user."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)
    assert user is not None

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
    _audit_log(
        "user_updated", new_username, f"email={email}, fullname={fullname}, enabled={enabled}"
    )
    flash(f"User '{new_username}' updated.", "success")

    return redirect(url_for("admin_users.list_users"))


@bp.route("/<path:username>/toggle", methods=["POST"])
@admin_required
def toggle_user(username: str):
    """Toggle user enabled/disabled (HTMX endpoint)."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)
    assert user is not None

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
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)
    assert user is not None

    user.rotate_login_salt()
    _audit_log("salt_rotated", username, "Login salt rotated, all sessions invalidated")
    flash(f"Login salt rotated for '{username}'. All sessions invalidated.", "success")

    return redirect(request.referrer or url_for("admin_users.list_users"))


@bp.route("/<path:username>/delete", methods=["POST"])
@admin_required
def delete_user(username: str):
    """Delete a user permanently."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)
    assert user is not None

    user.delete()
    _audit_log("user_deleted", username)
    flash(f"User '{username}' deleted.", "success")

    if _is_htmx():
        return ""
    return redirect(url_for("admin_users.list_users"))


@bp.route("/<path:username>/groups")
@admin_required
def user_groups(username: str):
    """Show user's group memberships."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)

    group_names = Group.get_groups_for_user(username)
    groups = [Group.get(name) for name in group_names]
    groups = [grp for grp in groups if grp is not None]

    return render_template("admin/user_groups.html", user=user, groups=groups)


@bp.route("/<path:username>/groups/add", methods=["POST"])
@admin_required
def add_user_group(username: str):
    """Add user to a group."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)

    group_name = request.form.get("group_name", "").strip()
    if not group_name:
        flash("Group name is required.", "error")
    else:
        group = Group.get(group_name)
        if group is None:
            flash(f"Group '{group_name}' not found.", "error")
        elif not group.add_member(username):
            flash(f"User '{username}' is already a member of '{group_name}'.", "error")
        else:
            _audit_log("member_added", f"{group_name}/{username}")
            flash(f"Added '{username}' to group '{group_name}'.", "success")

    if _is_htmx():
        group_names = Group.get_groups_for_user(username)
        groups = [Group.get(name) for name in group_names]
        groups = [grp for grp in groups if grp is not None]
        return render_template("admin/user_groups_list.html", user=user, groups=groups)
    return redirect(url_for("admin_users.user_groups", username=username))


@bp.route("/<path:username>/groups/<group_name>/remove", methods=["POST"])
@admin_required
def remove_user_group(username: str, group_name: str):
    """Remove user from a group."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)

    group = Group.get(group_name)
    if group and group.remove_member(username):
        _audit_log("member_removed", f"{group_name}/{username}")
        flash(f"Removed '{username}' from group '{group_name}'.", "success")
    else:
        flash(f"User '{username}' is not a member of '{group_name}'.", "error")

    if _is_htmx():
        group_names = Group.get_groups_for_user(username)
        groups = [Group.get(name) for name in group_names]
        groups = [grp for grp in groups if grp is not None]
        return render_template("admin/user_groups_list.html", user=user, groups=groups)
    return redirect(url_for("admin_users.user_groups", username=username))


@bp.route("/groups/search")
@admin_required
def search_groups():
    """Search groups for tom-select typeahead (returns JSON)."""
    query = request.args.get("q", "").strip().lower()
    all_groups = Group.get_all()
    results = []
    for grp in all_groups:
        if query and query not in grp.name.lower() and query not in grp.description.lower():
            continue
        results.append(
            {
                "value": grp.name,
                "text": grp.name,
                "description": grp.description,
            }
        )
        if len(results) >= 30:
            break
    return jsonify(results)
