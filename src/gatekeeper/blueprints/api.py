"""JSON API blueprint with API key authentication."""

import json
from functools import wraps

from flask import Blueprint, g, jsonify, request

from gatekeeper.db import get_db
from gatekeeper.models.api_key import ApiKey
from gatekeeper.models.app_setting import AppSetting
from gatekeeper.models.group import Group
from gatekeeper.models.user import User
from gatekeeper.services import token_service

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def api_key_required(f):
    """Decorator: require valid API key in Authorization header."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        raw_key = auth[7:]
        api_key = ApiKey.verify(raw_key)
        if api_key is None:
            return jsonify({"error": "Invalid or disabled API key"}), 401

        g.api_key = api_key
        return f(*args, **kwargs)

    return decorated


def _audit_log(action: str, target: str | None = None, details: str | None = None) -> None:
    from datetime import UTC, datetime

    db = get_db()
    now = datetime.now(UTC).isoformat()
    actor = f"api_key:{g.api_key.key_prefix}" if hasattr(g, "api_key") else None
    db.execute(
        "INSERT INTO audit_log (timestamp, actor, action, target, details) VALUES (?, ?, ?, ?, ?)",
        (now, actor, action, target, details),
    )


# --- Auth endpoints ---


@bp.route("/auth/resolve", methods=["POST"])
@api_key_required
def auth_resolve():
    """Resolve an identifier to a user."""
    data = request.get_json(silent=True) or {}
    identifier = data.get("identifier", "").strip()
    if not identifier:
        return jsonify({"error": "identifier is required"}), 400

    from gatekeeper.blueprints.auth import _resolve_identifier

    user, error = _resolve_identifier(identifier)
    if error:
        return jsonify({"error": error}), 404

    return jsonify(
        {
            "username": user.username,
            "email": user.email,
            "fullname": user.fullname,
            "enabled": user.enabled,
        }
    )


@bp.route("/auth/send-magic-link", methods=["POST"])
@api_key_required
def auth_send_magic_link():
    """Send a magic link email."""
    data = request.get_json(silent=True) or {}
    identifier = data.get("identifier", "").strip()
    callback_url = data.get("callback_url", "").strip()
    redirect_url = data.get("redirect_url", "/")

    if not identifier or not callback_url:
        return jsonify({"error": "identifier and callback_url are required"}), 400

    from gatekeeper.blueprints.auth import _resolve_identifier

    user, error = _resolve_identifier(identifier)
    if error:
        return jsonify({"error": error}), 404

    magic_token = token_service.create_magic_link_token(user.username, redirect_url=redirect_url)
    full_callback = (
        f"{callback_url}?token={magic_token}"
        if "?" not in callback_url
        else f"{callback_url}&token={magic_token}"
    )

    from gatekeeper.services.email_service import send_magic_link

    sent = send_magic_link(user.email, full_callback)
    if not sent:
        return jsonify({"error": "Failed to send email"}), 500

    _audit_log("api_magic_link_sent", user.username, f"Via API to {user.email}")
    return jsonify({"status": "sent", "email": user.email})


@bp.route("/auth/verify-magic-link", methods=["POST"])
@api_key_required
def auth_verify_magic_link():
    """Verify a magic link token."""
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    if not token:
        return jsonify({"error": "token is required"}), 400

    result = token_service.verify_magic_link_token(token)
    if result is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    user, redirect_url = result
    groups = Group.get_groups_for_user(user.username)

    return jsonify(
        {
            "username": user.username,
            "email": user.email,
            "fullname": user.fullname,
            "enabled": user.enabled,
            "redirect_url": redirect_url,
            "groups": groups,
        }
    )


@bp.route("/auth/create-token", methods=["POST"])
@api_key_required
def auth_create_token():
    """Create a signed auth token for a user."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    lifetime = data.get("lifetime_seconds", 86400)

    if not username:
        return jsonify({"error": "username is required"}), 400

    user = User.get(username)
    if user is None or not user.enabled:
        return jsonify({"error": "User not found or disabled"}), 404

    token = token_service.create_auth_token(user, lifetime_seconds=lifetime)
    _audit_log("api_token_created", username)

    return jsonify({"token": token, "username": username})


@bp.route("/auth/verify-token", methods=["POST"])
@api_key_required
def auth_verify_token():
    """Verify an auth token."""
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    if not token:
        return jsonify({"error": "token is required"}), 400

    user = token_service.verify_auth_token(token)
    if user is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    groups = Group.get_groups_for_user(user.username)

    return jsonify(
        {
            "username": user.username,
            "email": user.email,
            "fullname": user.fullname,
            "enabled": user.enabled,
            "groups": groups,
        }
    )


# --- User endpoints ---


@bp.route("/users")
@api_key_required
def list_users():
    """List users with optional filtering."""
    search = request.args.get("search")
    enabled_only = request.args.get("enabled_only", "false").lower() == "true"
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))

    users = User.get_all(enabled_only=enabled_only, search=search, limit=limit, offset=offset)
    total = User.count(enabled_only=enabled_only)

    return jsonify(
        {
            "users": [
                {
                    "username": u.username,
                    "email": u.email,
                    "fullname": u.fullname,
                    "enabled": u.enabled,
                    "created_at": u.created_at,
                    "updated_at": u.updated_at,
                }
                for u in users
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@bp.route("/users/<path:username>")
@api_key_required
def get_user(username: str):
    """Get a single user."""
    user = User.get(username)
    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify(
        {
            "username": user.username,
            "email": user.email,
            "fullname": user.fullname,
            "enabled": user.enabled,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }
    )


@bp.route("/users", methods=["POST"])
@api_key_required
def create_user():
    """Create a new user."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()

    if not username or not email:
        return jsonify({"error": "username and email are required"}), 400

    if User.get(username):
        return jsonify({"error": "User already exists"}), 409

    user = User.create(
        username=username,
        email=email,
        fullname=data.get("fullname", ""),
        enabled=data.get("enabled", True),
    )

    _audit_log("api_user_created", username, json.dumps({"email": email}))

    return jsonify(
        {
            "username": user.username,
            "email": user.email,
            "fullname": user.fullname,
            "enabled": user.enabled,
            "created_at": user.created_at,
        }
    ), 201


@bp.route("/users/<path:username>", methods=["PATCH"])
@api_key_required
def update_user(username: str):
    """Update a user."""
    user = User.get(username)
    if user is None:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json(silent=True) or {}
    user.update(
        email=data.get("email"),
        fullname=data.get("fullname"),
        enabled=data.get("enabled"),
    )

    _audit_log("api_user_updated", username, json.dumps(data))

    return jsonify(
        {
            "username": user.username,
            "email": user.email,
            "fullname": user.fullname,
            "enabled": user.enabled,
            "updated_at": user.updated_at,
        }
    )


@bp.route("/users/<path:username>/rotate-salt", methods=["POST"])
@api_key_required
def rotate_user_salt(username: str):
    """Rotate a user's login salt, invalidating their sessions."""
    user = User.get(username)
    if user is None:
        return jsonify({"error": "User not found"}), 404

    user.rotate_login_salt()
    _audit_log("api_salt_rotated", username)

    return jsonify({"status": "rotated", "username": username})


@bp.route("/users/<path:username>/groups")
@api_key_required
def get_user_groups(username: str):
    """Get groups for a user."""
    user = User.get(username)
    if user is None:
        return jsonify({"error": "User not found"}), 404

    groups = Group.get_groups_for_user(username)
    return jsonify({"username": username, "groups": groups})


# --- Group endpoints ---


@bp.route("/groups")
@api_key_required
def list_groups():
    """List all groups."""
    groups = Group.get_all()
    return jsonify(
        {
            "groups": [
                {
                    "name": g.name,
                    "description": g.description,
                    "created_at": g.created_at,
                    "updated_at": g.updated_at,
                }
                for g in groups
            ]
        }
    )


@bp.route("/groups/<name>")
@api_key_required
def get_group(name: str):
    """Get a single group."""
    group = Group.get(name)
    if group is None:
        return jsonify({"error": "Group not found"}), 404

    return jsonify(
        {
            "name": group.name,
            "description": group.description,
            "created_at": group.created_at,
            "updated_at": group.updated_at,
        }
    )


@bp.route("/groups", methods=["POST"])
@api_key_required
def create_group():
    """Create a new group."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    if Group.get(name):
        return jsonify({"error": "Group already exists"}), 409

    group = Group.create(name=name, description=data.get("description", ""))
    _audit_log("api_group_created", name)

    return jsonify(
        {
            "name": group.name,
            "description": group.description,
            "created_at": group.created_at,
        }
    ), 201


@bp.route("/groups/<name>", methods=["PATCH"])
@api_key_required
def update_group(name: str):
    """Update a group."""
    group = Group.get(name)
    if group is None:
        return jsonify({"error": "Group not found"}), 404

    data = request.get_json(silent=True) or {}
    group.update(description=data.get("description"))
    _audit_log("api_group_updated", name)

    return jsonify(
        {
            "name": group.name,
            "description": group.description,
            "updated_at": group.updated_at,
        }
    )


@bp.route("/groups/<name>", methods=["DELETE"])
@api_key_required
def delete_group(name: str):
    """Delete a group."""
    if name in ("admin", "standard"):
        return jsonify({"error": "Cannot delete built-in groups"}), 400

    group = Group.get(name)
    if group is None:
        return jsonify({"error": "Group not found"}), 404

    group.delete()
    _audit_log("api_group_deleted", name)

    return jsonify({"status": "deleted"})


@bp.route("/groups/<name>/members")
@api_key_required
def list_group_members(name: str):
    """List members of a group."""
    group = Group.get(name)
    if group is None:
        return jsonify({"error": "Group not found"}), 404

    members = group.get_members()
    return jsonify({"group": name, "members": members})


@bp.route("/groups/<name>/members", methods=["POST"])
@api_key_required
def add_group_member(name: str):
    """Add a member to a group."""
    group = Group.get(name)
    if group is None:
        return jsonify({"error": "Group not found"}), 404

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "username is required"}), 400

    if User.get(username) is None:
        return jsonify({"error": "User not found"}), 404

    if not group.add_member(username):
        return jsonify({"error": "User is already a member"}), 409

    _audit_log("api_member_added", f"{name}/{username}")
    return jsonify({"status": "added", "group": name, "username": username}), 201


@bp.route("/groups/<name>/members/<path:username>", methods=["DELETE"])
@api_key_required
def remove_group_member(name: str, username: str):
    """Remove a member from a group."""
    group = Group.get(name)
    if group is None:
        return jsonify({"error": "Group not found"}), 404

    if not group.remove_member(username):
        return jsonify({"error": "User is not a member"}), 404

    _audit_log("api_member_removed", f"{name}/{username}")
    return jsonify({"status": "removed"})


# --- System endpoints ---


@bp.route("/system/app-salt")
@api_key_required
def get_app_salt():
    """Get the current app salt."""
    salt = AppSetting.get_app_salt()
    return jsonify({"app_salt": salt})


@bp.route("/system/rotate-app-salt", methods=["POST"])
@api_key_required
def rotate_app_salt():
    """Rotate the global app salt, invalidating all sessions."""
    new_salt = AppSetting.rotate_app_salt()
    _audit_log("api_app_salt_rotated", details="All sessions invalidated")
    return jsonify({"status": "rotated", "app_salt": new_salt})
