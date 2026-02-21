"""Admin blueprint for user management."""

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.wrappers import Response

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

    from gatekeeper.models.user import _USER_COLUMNS

    offset = (page - 1) * per_page
    rows = db.execute(
        f"SELECT {_USER_COLUMNS} FROM user{where} ORDER BY {col} {direction} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()

    users = [User._from_row(r) for r in rows]
    return users, total


@bp.route("/")
@admin_required
def list_users() -> str:
    """List users with search, sort, and pagination."""
    search = request.args.get("search", "").strip() or None
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(1, min(200, int(request.args.get("per_page", 50))))
    sort = request.args.get("sort", "username")
    order = request.args.get("order", "asc")

    users, total = _get_users_page(search, page, per_page, sort, order)
    total_pages = max(1, (total + per_page - 1) // per_page)

    # Build username -> gatekeeper groups and LDAP groups flag
    user_gk_groups: dict[str, list[str]] = {}
    user_has_ldap_groups: dict[str, bool] = {}
    if users:
        db = get_db()
        usernames = [u.username for u in users]
        placeholders = ",".join("?" * len(usernames))
        rows = db.execute(
            f"SELECT gu.username, gu.group_name, g.source "
            f"FROM group_user gu JOIN grp g ON gu.group_name = g.name "
            f"WHERE gu.username IN ({placeholders}) ORDER BY gu.group_name",
            usernames,
        ).fetchall()
        for row in rows:
            uname = str(row[0])
            gname = str(row[1])
            source = str(row[2])
            if source == "ldap":
                user_has_ldap_groups[uname] = True
            else:
                user_gk_groups.setdefault(uname, []).append(gname)

    context = {
        "users": users,
        "user_groups": user_gk_groups,
        "user_has_ldap_groups": user_has_ldap_groups,
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
def export() -> Response:
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
def create_form() -> str:
    """Show create user form."""
    return render_template("admin/user_form.html", user=None, is_ldap=False)


@bp.route("/create", methods=["POST"])
@admin_required
def create_user() -> Response:
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
def ldap_provision_form() -> str | Response:
    """Show LDAP user provisioning form."""
    from gatekeeper.services.ldap_service import is_ldap_enabled

    if not is_ldap_enabled():
        flash("LDAP is not enabled in configuration.", "error")
        return redirect(url_for("admin_users.list_users"))

    return render_template("admin/user_ldap_provision.html")


@bp.route("/ldap-provision", methods=["POST"])
@admin_required
def ldap_provision() -> Response:
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

    # Extract domain from username and resolve to config casing
    from gatekeeper.services.ldap_service import resolve_domain

    raw_domain = ldap_user.username.split("\\", 1)[0] if "\\" in ldap_user.username else ""
    ldap_domain = resolve_domain(raw_domain) or raw_domain

    # Create the user with extended fields
    User.create(
        username=ldap_user.username,
        email=ldap_user.email,
        fullname=ldap_user.fullname,
        enabled=True,
        ldap_domain=ldap_domain,
        given_name=ldap_user.given_name,
        mail_nickname=ldap_user.mail_nickname,
        title=ldap_user.title,
        department=ldap_user.department,
        manager=ldap_user.manager,
        telephone_number=ldap_user.telephone_number,
        mobile_number=ldap_user.mobile_number,
    )

    # Add to standard group
    standard = Group.get("standard")
    if standard:
        standard.add_member(ldap_user.username)

    # Sync LDAP groups
    for group_cn in ldap_user.groups or []:
        grp = Group.get(group_cn)
        if not grp:
            grp = Group.create(name=group_cn, source="ldap")
        grp.add_member(ldap_user.username)

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
def edit_form(username: str) -> str:
    """Show edit user form."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)
    assert user is not None
    groups = Group.get_groups_for_user(username)
    db = get_db()
    prop_rows = db.execute(
        "SELECT app, key, value FROM user_property WHERE LOWER(username) = ? ORDER BY app, key",
        (username,),
    ).fetchall()
    properties = [{"app": r[0], "key": r[1], "value": r[2]} for r in prop_rows]
    return render_template(
        "admin/user_form.html",
        user=user,
        groups=groups,
        properties=properties,
        is_ldap=user.is_ldap,
    )


@bp.route("/<path:username>/edit", methods=["POST"])
@admin_required
def edit_user(username: str) -> Response:
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

    if user.is_ldap:
        # For LDAP users, only update enabled status (LDAP fields are read-only)
        user.update(enabled=enabled)
    else:
        # For non-LDAP users, update all editable fields
        given_name = request.form.get("given_name", "").strip()
        mail_nickname = request.form.get("mail_nickname", "").strip()
        title = request.form.get("title", "").strip()
        department = request.form.get("department", "").strip()
        manager = request.form.get("manager", "").strip()
        telephone_number = request.form.get("telephone_number", "").strip()
        mobile_number = request.form.get("mobile_number", "").strip()

        user.update(
            email=email or None,
            fullname=fullname,
            enabled=enabled,
            given_name=given_name,
            mail_nickname=mail_nickname,
            title=title,
            department=department,
            manager=manager,
            telephone_number=telephone_number,
            mobile_number=mobile_number,
        )

    _audit_log(
        "user_updated", new_username, f"email={email}, fullname={fullname}, enabled={enabled}"
    )
    flash(f"User '{new_username}' updated.", "success")

    return redirect(url_for("admin_users.list_users"))


@bp.route("/<path:username>/toggle", methods=["POST"])
@admin_required
def toggle_user(username: str) -> str:
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

    groups_with_source = Group.get_groups_for_user_with_source(username)
    gk_groups = [name for name, source in groups_with_source if source != "ldap"]
    has_ldap = any(source == "ldap" for _, source in groups_with_source)
    return render_template(
        "admin/user_row.html",
        user=user,
        user_groups={username: gk_groups},
        user_has_ldap_groups={username: has_ldap} if has_ldap else {},
    )


@bp.route("/<path:username>/rotate-salt", methods=["POST"])
@admin_required
def rotate_salt(username: str) -> Response:
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
def delete_user(username: str) -> str | Response:
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
def user_groups(username: str) -> str:
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
def add_user_group(username: str) -> str | Response:
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
def remove_user_group(username: str, group_name: str) -> str | Response:
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
def search_groups() -> Response:
    """Search groups for tom-select typeahead (returns JSON)."""
    query = request.args.get("q", "").strip().lower()
    all_groups = Group.get_all()
    results = []
    for grp in all_groups:
        if grp.source == "ldap":
            continue
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


def _refresh_ldap_user(user: User) -> tuple[bool, str]:
    """Re-query LDAP and update a user's extended fields and group memberships.

    Returns (success, message).
    """
    from flask import current_app

    from gatekeeper.services.ldap_service import (
        is_ldap_enabled,
        lookup_full_details,
        resolve_domain,
    )

    if not is_ldap_enabled():
        return False, "LDAP is not enabled."

    if not user.is_ldap:
        return False, f"User '{user.username}' is not an LDAP user."

    domain = resolve_domain(user.ldap_domain)
    if not domain:
        return False, f"No configured LDAP domain matches '{user.ldap_domain}'."

    bare_username = user.username.split("\\", 1)[1] if "\\" in user.username else user.username

    try:
        ldap_user = lookup_full_details(domain, bare_username)
    except Exception as exc:
        current_app.logger.error(f"LDAP error refreshing {user.username}: {exc}")
        return False, f"LDAP error for '{user.username}': {exc}"
    if not ldap_user:
        return False, f"User '{user.username}' not found in LDAP domain '{domain}'."

    # Update extended fields (also fix ldap_domain to config casing)
    user.update(
        ldap_domain=domain,
        email=ldap_user.email,
        fullname=ldap_user.fullname,
        given_name=ldap_user.given_name,
        mail_nickname=ldap_user.mail_nickname,
        title=ldap_user.title,
        department=ldap_user.department,
        manager=ldap_user.manager,
        telephone_number=ldap_user.telephone_number,
        mobile_number=ldap_user.mobile_number,
    )

    # Sync LDAP group memberships
    current_ldap_groups = {
        name
        for name, source in Group.get_groups_for_user_with_source(user.username)
        if source == "ldap"
    }
    desired_ldap_groups = set(ldap_user.groups or [])

    # Add new LDAP groups
    for group_cn in desired_ldap_groups - current_ldap_groups:
        grp = Group.get(group_cn)
        if not grp:
            grp = Group.create(name=group_cn, source="ldap")
        grp.add_member(user.username)

    # Remove stale LDAP groups
    for group_cn in current_ldap_groups - desired_ldap_groups:
        grp = Group.get(group_cn)
        if grp:
            grp.remove_member(user.username)

    current_app.logger.info(f"Refreshed LDAP user: {user.username}")
    return True, f"User '{user.username}' refreshed from LDAP."


@bp.route("/<path:username>/refresh-ldap", methods=["POST"])
@admin_required
def refresh_ldap(username: str) -> str | Response:
    """Refresh a single user from LDAP."""
    username = username.lower()
    user = User.get(username)
    if user is None:
        abort(404)
    assert user is not None

    success, message = _refresh_ldap_user(user)
    if success:
        _audit_log("user_ldap_refreshed", username, message)
        flash(message, "success")
    else:
        flash(message, "error")

    if _is_htmx():
        resp = make_response("")
        resp.headers["HX-Redirect"] = url_for("admin_users.edit_form", username=username)
        return resp

    return redirect(url_for("admin_users.edit_form", username=username))


@bp.route("/refresh-all-ldap", methods=["POST"])
@admin_required
def refresh_all_ldap() -> str | Response:
    """Refresh LDAP users one at a time via HTMX chaining.

    Each request processes one user and returns a progress fragment that
    auto-triggers the next request, keeping each within gunicorn timeout.
    """
    from gatekeeper.services.ldap_service import is_ldap_enabled

    if not is_ldap_enabled():
        flash("LDAP is not enabled.", "error")
        return redirect(url_for("admin_users.list_users"))

    db = get_db()
    usernames = [
        str(r[0])
        for r in db.execute(
            "SELECT username FROM user WHERE ldap_domain != '' ORDER BY username"
        ).fetchall()
    ]
    total = len(usernames)

    if total == 0:
        if _is_htmx():
            return "<p>No LDAP users to refresh.</p>"
        flash("No LDAP users to refresh.", "info")
        return redirect(url_for("admin_users.list_users"))

    offset = int(request.form.get("offset", request.args.get("offset", 0)))
    refreshed = int(request.form.get("refreshed", request.args.get("refreshed", 0)))
    failed = int(request.form.get("failed", request.args.get("failed", 0)))

    # Process one user
    if offset < total:
        user = User.get(usernames[offset])
        if user:
            success, _ = _refresh_ldap_user(user)
            if success:
                refreshed += 1
            else:
                failed += 1
        offset += 1

    # More users to process — return progress with auto-trigger for next
    if offset < total:
        next_url = url_for(
            "admin_users.refresh_all_ldap",
            offset=offset,
            refreshed=refreshed,
            failed=failed,
        )
        return (
            f'<div hx-post="{next_url}" hx-trigger="load" '
            f'hx-target="#ldap-refresh-status" hx-swap="innerHTML">'
            f"<p>Refreshing LDAP users... ({offset}/{total})</p>"
            f'<progress value="{offset}" max="{total}"></progress>'
            f"</div>"
        )

    # All done
    _audit_log("users_ldap_refreshed_all", details=f"refreshed={refreshed}, failed={failed}")
    status = "success" if not failed else "warning"
    msg = f"Refreshed {refreshed} LDAP user(s). {failed} failed."

    if _is_htmx():
        icon = "&#x2705;" if not failed else "&#x26A0;&#xFE0F;"
        return f"<p>{icon} {msg}</p>"

    flash(msg, status)
    return redirect(url_for("admin_users.list_users"))
