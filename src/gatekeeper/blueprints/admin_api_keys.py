"""Admin blueprint for API key management (HTMX)."""

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.models.api_key import ApiKey

bp = Blueprint("admin_api_keys", __name__, url_prefix="/admin/api-keys")


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


@bp.route("/")
@admin_required
def index():
    """List all API keys."""
    keys = ApiKey.get_all()
    return render_template("admin/api_keys.html", keys=keys)


@bp.route("/generate", methods=["POST"])
@admin_required
def generate():
    """Generate a new API key."""
    description = request.form.get("description", "").strip()
    if not description:
        flash("Description is required.", "error")
        return redirect(url_for("admin_api_keys.index"))

    api_key = ApiKey.generate(description=description)

    _audit_log("api_key_generated", str(api_key.id), f"Description: {description}")

    return redirect(url_for("admin_api_keys.index"))


@bp.route("/<int:key_id>/toggle", methods=["POST"])
@admin_required
def toggle(key_id: int):
    """Toggle an API key between enabled and disabled."""
    api_key = ApiKey.get(key_id)
    if api_key is None:
        flash("API key not found.", "error")
        return redirect(url_for("admin_api_keys.index"))

    if api_key.enabled:
        api_key.disable()
        _audit_log("api_key_disabled", str(api_key.id))
    else:
        api_key.enable()
        _audit_log("api_key_enabled", str(api_key.id))

    if _is_htmx():
        return render_template("admin/api_key_row.html", key=api_key)

    return redirect(url_for("admin_api_keys.index"))


@bp.route("/<int:key_id>/delete", methods=["POST"])
@admin_required
def delete(key_id: int):
    """Delete an API key."""
    api_key = ApiKey.get(key_id)
    if api_key is None:
        flash("API key not found.", "error")
        return redirect(url_for("admin_api_keys.index"))

    key_id_str = str(api_key.id)
    api_key.delete()
    _audit_log("api_key_deleted", key_id_str)

    if _is_htmx():
        return "", 200

    flash("API key deleted.", "success")
    return redirect(url_for("admin_api_keys.index"))
