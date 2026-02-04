"""Admin blueprint for group management (HTMX)."""

from datetime import UTC, datetime

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.models.group import Group
from gatekeeper.models.user import User

bp = Blueprint("admin_groups", __name__, url_prefix="/admin/groups")

BUILTIN_GROUPS = ("admin", "standard")


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


def _groups_with_counts() -> list[dict]:
    """Get all groups with their member counts."""
    db = get_db()
    rows = db.execute(
        "SELECT g.name, g.description, g.created_at, g.updated_at, "
        "COUNT(gu.username) AS member_count "
        "FROM grp g LEFT JOIN group_user gu ON g.name = gu.group_name "
        "GROUP BY g.name ORDER BY g.name"
    ).fetchall()
    return [
        {
            "name": row[0],
            "description": row[1],
            "created_at": row[2],
            "updated_at": row[3],
            "member_count": row[4],
        }
        for row in rows
    ]


@bp.route("/")
@admin_required
def list_groups():
    """List all groups with member counts."""
    groups = _groups_with_counts()
    if _is_htmx():
        return render_template("admin/groups_table.html", groups=groups)
    return render_template("admin/groups.html", groups=groups)


@bp.route("/create", methods=["GET"])
@admin_required
def create_form():
    """Show the create group form."""
    return render_template("admin/group_form.html", group=None)


@bp.route("/create", methods=["POST"])
@admin_required
def create_group():
    """Create a new group."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()

    if not name:
        flash("Group name is required.", "error")
        return redirect(url_for("admin_groups.create_form"))

    if Group.get(name):
        flash(f"Group '{name}' already exists.", "error")
        return redirect(url_for("admin_groups.create_form"))

    Group.create(name=name, description=description)
    _audit_log("group_created", name, f"Description: {description}")
    flash(f"Group '{name}' created.", "success")
    return redirect(url_for("admin_groups.list_groups"))


@bp.route("/<name>/edit", methods=["GET"])
@admin_required
def edit_form(name: str):
    """Show the edit group form."""
    group = Group.get(name)
    if group is None:
        abort(404)
    return render_template("admin/group_form.html", group=group)


@bp.route("/<name>/edit", methods=["POST"])
@admin_required
def edit_group(name: str):
    """Update a group."""
    group = Group.get(name)
    if group is None:
        abort(404)

    description = request.form.get("description", "").strip()
    group.update(description=description)
    _audit_log("group_updated", name, f"Description: {description}")
    flash(f"Group '{name}' updated.", "success")
    return redirect(url_for("admin_groups.list_groups"))


@bp.route("/<name>/delete", methods=["POST"])
@admin_required
def delete_group(name: str):
    """Delete a group (refuse built-in groups)."""
    if name in BUILTIN_GROUPS:
        flash(f"Cannot delete built-in group '{name}'.", "error")
        return redirect(url_for("admin_groups.list_groups"))

    group = Group.get(name)
    if group is None:
        abort(404)

    group.delete()
    _audit_log("group_deleted", name)
    flash(f"Group '{name}' deleted.", "success")
    return redirect(url_for("admin_groups.list_groups"))


@bp.route("/<name>/members", methods=["GET"])
@admin_required
def members(name: str):
    """Show group members management page."""
    group = Group.get(name)
    if group is None:
        abort(404)

    member_names = group.get_members()
    member_users = [User.get(u) for u in member_names]
    member_users = [u for u in member_users if u is not None]
    return render_template("admin/group_members.html", group=group, members=member_users)


def _get_member_users(group: Group) -> list[User]:
    """Get full User objects for all members of a group."""
    member_names = group.get_members()
    users = [User.get(u) for u in member_names]
    return [u for u in users if u is not None]


@bp.route("/<name>/members", methods=["POST"])
@admin_required
def add_member(name: str):
    """Add a member to the group."""
    group = Group.get(name)
    if group is None:
        abort(404)

    username = request.form.get("username", "").strip()
    if not username:
        flash("Username is required.", "error")
    elif User.get(username) is None:
        flash(f"User '{username}' not found.", "error")
    elif not group.add_member(username):
        flash(f"User '{username}' is already a member of '{name}'.", "error")
    else:
        _audit_log("member_added", f"{name}/{username}")
        flash(f"Added '{username}' to group '{name}'.", "success")

    if _is_htmx():
        return render_template("admin/group_members_list.html", group=group, members=_get_member_users(group))
    return redirect(url_for("admin_groups.members", name=name))


@bp.route("/<name>/members/<path:username>/remove", methods=["POST"])
@admin_required
def remove_member(name: str, username: str):
    """Remove a member from the group."""
    group = Group.get(name)
    if group is None:
        abort(404)

    if group.remove_member(username):
        _audit_log("member_removed", f"{name}/{username}")
        flash(f"Removed '{username}' from group '{name}'.", "success")
    else:
        flash(f"User '{username}' is not a member of '{name}'.", "error")

    if _is_htmx():
        return render_template("admin/group_members_list.html", group=group, members=_get_member_users(group))
    return redirect(url_for("admin_groups.members", name=name))


@bp.route("/users/search")
@admin_required
def search_users():
    """Search users for tom-select typeahead (returns JSON)."""
    query = request.args.get("q", "").strip().lower()
    all_users = User.get_all(limit=500)
    results = []
    for user in all_users:
        if query and query not in user.username.lower() and query not in user.email.lower() and query not in user.fullname.lower():
            continue
        results.append({
            "value": user.username,
            "text": user.username,
            "email": user.email,
            "fullname": user.fullname,
        })
        if len(results) >= 30:
            break
    return jsonify(results)


@bp.route("/copy-memberships", methods=["POST"])
@admin_required
def copy_memberships():
    """Copy all group memberships from source user to target user."""
    source_username = request.form.get("source_username", "").strip()
    target_username = request.form.get("target_username", "").strip()

    if not source_username or not target_username:
        flash("Both source and target usernames are required.", "error")
        return redirect(url_for("admin_groups.list_groups"))

    if User.get(source_username) is None:
        flash(f"Source user '{source_username}' not found.", "error")
        return redirect(url_for("admin_groups.list_groups"))

    if User.get(target_username) is None:
        flash(f"Target user '{target_username}' not found.", "error")
        return redirect(url_for("admin_groups.list_groups"))

    source_groups = Group.get_groups_for_user(source_username)
    added = []
    for group_name in source_groups:
        group = Group.get(group_name)
        if group and group.add_member(target_username):
            added.append(group_name)

    _audit_log(
        "memberships_copied",
        f"{source_username} -> {target_username}",
        f"Groups added: {', '.join(added) if added else 'none (already member of all)'}",
    )

    if added:
        flash(
            f"Copied {len(added)} group membership(s) from '{source_username}' to '{target_username}': {', '.join(added)}.",
            "success",
        )
    else:
        flash(
            f"'{target_username}' is already a member of all groups that '{source_username}' belongs to.",
            "info",
        )
    return redirect(url_for("admin_groups.list_groups"))
