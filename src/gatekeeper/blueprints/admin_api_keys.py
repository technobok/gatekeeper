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
    api_key, raw_key = ApiKey.generate(description=description)

    _audit_log("api_key_generated", api_key.key_prefix, f"Description: {description}")

    flash(f"New API key (copy now, it will not be shown again): {raw_key}", "success")
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
        _audit_log("api_key_disabled", api_key.key_prefix)
    else:
        api_key.enable()
        _audit_log("api_key_enabled", api_key.key_prefix)

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

    prefix = api_key.key_prefix
    api_key.delete()
    _audit_log("api_key_deleted", prefix)

    flash("API key deleted.", "success")
    return redirect(url_for("admin_api_keys.index"))
