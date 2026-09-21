"""Admin blueprint for single sign-on settings."""

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.wrappers import Response

from gatekeeper.blueprints.auth import admin_required
from gatekeeper.db import get_db
from gatekeeper.models.app_setting import AppSetting

bp = Blueprint("admin_sso", __name__, url_prefix="/admin/sso")

# Everything the page may write. Listing them explicitly means a stray form field
# cannot set an unrelated setting.
_TEXT_SETTINGS = (
    "oidc.issuer",
    "oidc.client_id",
    "oidc.client_secret",
    "oidc.scopes",
    "oidc.provider_name",
)
_MODES = ("off", "proxy_header", "oidc")


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
def index() -> str:
    """Show the current single sign-on configuration."""
    from gatekeeper.services import oidc_service

    state = oidc_service.describe()
    return render_template(
        "admin/sso.html",
        state=state,
        modes=_MODES,
        callback_url=_safe_callback_url(),
    )


def _safe_callback_url() -> str:
    """The redirect URI to register with the provider.

    Shown on the page because getting it wrong is the most common way to waste an
    afternoon, and it cannot be guessed from the outside.
    """
    try:
        return url_for("auth.sso_callback", _external=True)
    except Exception:
        return "(could not be determined)"


@bp.route("/", methods=["POST"])
@admin_required
def save() -> Response:
    """Save the configuration."""
    mode = request.form.get("sso.mode", "off").strip().lower()
    if mode not in _MODES:
        flash(f"Unknown mode '{mode}'.", "error")
        return redirect(url_for("admin_sso.index"))

    previous_secret = AppSetting.get("oidc.client_secret") or ""

    AppSetting.set("sso.mode", mode)
    for key in _TEXT_SETTINGS:
        AppSetting.set(key, request.form.get(key, "").strip())

    # The secret is shown in the form, so what comes back is the whole truth --
    # emptying the box clears it, and there is no separate gesture to learn.
    if (request.form.get("oidc.client_secret", "").strip()) != previous_secret:
        _audit_log("sso_secret_changed")

    _audit_log("sso_settings_saved", details=f"mode={mode}")
    flash("Single sign-on settings saved.", "success")
    return redirect(url_for("admin_sso.index"))
