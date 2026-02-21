"""Authentication blueprint - login/verify/logout (HTMX)."""

import logging
from collections.abc import Callable
from typing import Any

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.wrappers import Response

from gatekeeper.db import get_db
from gatekeeper.models.group import Group
from gatekeeper.models.user import User
from gatekeeper.services import email_service, token_service

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/auth")


def _resolve_identifier(identifier: str) -> tuple[User | None, str | None]:
    """Resolve a login identifier to a user.

    Returns (user, error_message). If user is None, error_message explains why.

    Identifier formats:
    1. Email (contains @): look up by email; if >1 match, reject
    2. domain\\username (contains \\): direct DB lookup, then LDAP
    3. Bare username: direct DB lookup, then LDAP across all domains
    """
    identifier = identifier.strip()
    if not identifier:
        return None, "Please enter your email or username."

    if "@" in identifier:
        # Email lookup
        users = User.get_by_email(identifier)
        if len(users) == 1:
            return users[0], None
        elif len(users) > 1:
            return None, "Multiple accounts share this email. Please use your username."
        else:
            # Try LDAP
            ldap_user = _try_ldap_email(identifier)
            if ldap_user:
                return ldap_user, None
            return None, "No account found for this email."

    elif "\\" in identifier:
        # domain\username format
        user = User.get(identifier)
        if user and user.enabled:
            return user, None
        # Try LDAP for this domain
        parts = identifier.split("\\", 1)
        domain = parts[0]
        username = parts[1]
        ldap_user = _try_ldap_domain(domain, username)
        if ldap_user:
            return ldap_user, None
        if user and not user.enabled:
            return None, "This account is disabled."
        return None, "No account found for this username."

    else:
        # Bare username
        user = User.get(identifier)
        if user and user.enabled:
            return user, None
        # Try LDAP across all domains
        ldap_user = _try_ldap_bare(identifier)
        if ldap_user:
            return ldap_user, None
        if user and not user.enabled:
            return None, "This account is disabled."
        return None, "No account found for this username."


def _try_ldap_email(email: str) -> User | None:
    """Try LDAP lookup by email, auto-provisioning if found."""
    from gatekeeper.services.ldap_service import is_ldap_enabled, lookup_by_email

    if not is_ldap_enabled():
        return None

    ldap_user = lookup_by_email(email)
    if ldap_user:
        return _auto_provision(ldap_user)
    return None


def _try_ldap_domain(domain: str, username: str) -> User | None:
    """Try LDAP lookup for a specific domain, auto-provisioning if found."""
    from gatekeeper.services.ldap_service import is_ldap_enabled, lookup_by_username

    if not is_ldap_enabled():
        return None

    ldap_user = lookup_by_username(domain, username)
    if ldap_user:
        return _auto_provision(ldap_user)
    return None


def _try_ldap_bare(username: str) -> User | None:
    """Try LDAP lookup across all configured domains."""
    from gatekeeper.services.ldap_service import is_ldap_enabled, lookup_by_username

    if not is_ldap_enabled():
        return None

    domains = current_app.config.get("LDAP_DOMAINS", [])
    for domain in domains:
        ldap_user = lookup_by_username(domain, username)
        if ldap_user:
            return _auto_provision(ldap_user)
    return None


def _auto_provision(ldap_user: Any) -> User:
    """Auto-create a user from LDAP data, add to standard group, and sync LDAP groups."""
    from gatekeeper.services.ldap_service import LdapUser

    assert isinstance(ldap_user, LdapUser)
    username = ldap_user.username
    user = User.get(username)
    if user:
        return user

    # Extract domain from username (DOMAIN\sam)
    ldap_domain = username.split("\\", 1)[0] if "\\" in username else ""

    user = User.create(
        username=username,
        email=ldap_user.email,
        fullname=ldap_user.fullname,
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
    group = Group.get("standard")
    if group:
        group.add_member(username)

    # Sync LDAP groups
    for group_cn in ldap_user.groups or []:
        grp = Group.get(group_cn)
        if not grp:
            grp = Group.create(name=group_cn, source="ldap")
        grp.add_member(username)

    current_app.logger.info(f"Auto-provisioned LDAP user: {username} ({ldap_user.email})")
    _audit_log("auto_provision", username, f"LDAP auto-provisioned: {ldap_user.email}")
    return user


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


@bp.route("/login", methods=["GET", "POST"])
def login() -> str | Response:
    """Show login form or process login request.

    SSO mode: when ``callback_url`` is provided, the magic link points to the
    calling app's verify endpoint instead of Gatekeeper's own, and the
    admin-only restriction is skipped.
    """
    # SSO parameters (passed as query params on GET, hidden fields on POST)
    if request.method == "GET":
        app_name = request.args.get("app_name", "")
        sso_callback_url = request.args.get("callback_url", "")
        next_url = request.args.get("next", url_for("index"))
        return render_template(
            "auth/login.html",
            next_url=next_url,
            app_name=app_name,
            callback_url=sso_callback_url,
        )

    identifier = request.form.get("identifier", "").strip()
    next_url = request.form.get("next", url_for("index"))
    app_name = request.form.get("app_name", "")
    sso_callback_url = request.form.get("callback_url", "")
    sso_mode = bool(sso_callback_url)

    tpl_ctx = dict(
        next_url=next_url,
        identifier=identifier,
        app_name=app_name,
        callback_url=sso_callback_url,
    )

    user, error = _resolve_identifier(identifier)
    if error:
        flash(error, "error")
        if _is_htmx():
            return render_template("auth/login.html", **tpl_ctx)
        return redirect(
            url_for("auth.login", next=next_url, app_name=app_name, callback_url=sso_callback_url)
        )
    assert user is not None

    # Admin-only check applies only when logging into Gatekeeper itself
    if not sso_mode and not Group.user_in_group(user.username, "admin"):
        flash("Access is restricted to administrators.", "error")
        _audit_log("login_rejected", user.username, "Non-admin login attempt")
        if _is_htmx():
            return render_template("auth/login.html", **tpl_ctx)
        return redirect(url_for("auth.login", next=next_url))

    # Create magic link token
    magic_token = token_service.create_magic_link_token(user.username, redirect_url=next_url)

    # Build the verify URL: SSO mode points to the calling app, otherwise Gatekeeper's own verify
    if sso_mode:
        sep = "&" if "?" in sso_callback_url else "?"
        verify_url = f"{sso_callback_url}{sep}token={magic_token}"
    else:
        verify_url = url_for("auth.verify", token=magic_token, _external=True)

    display_name = app_name or "Gatekeeper"
    sent = email_service.send_magic_link(user.email, verify_url, app_name=display_name)
    if not sent:
        logger.error(f"Failed to send magic link email to {user.email} for user {user.username}")
        flash("Failed to send login email. Please try again.", "error")
        if _is_htmx():
            return render_template("auth/login.html", **tpl_ctx)
        return redirect(
            url_for("auth.login", next=next_url, app_name=app_name, callback_url=sso_callback_url)
        )

    _audit_log("magic_link_sent", user.username, f"Email sent to {user.email} (app={display_name})")

    return render_template(
        "auth/login_sent.html",
        email=user.email,
        app_name=app_name,
        callback_url=sso_callback_url,
    )


@bp.route("/verify")
def verify() -> Response:
    """Verify a magic link token and set the auth cookie."""
    token = request.args.get("token")
    if not token:
        abort(400)
    assert token is not None

    result = token_service.verify_magic_link_token(token)
    if result is None:
        flash("This login link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("auth.login"))
    assert result is not None

    user, redirect_url = result

    # Re-check admin membership (user may have been removed since link was sent)
    if not Group.user_in_group(user.username, "admin"):
        flash("Access is restricted to administrators.", "error")
        _audit_log("login_rejected", user.username, "Non-admin at verification")
        return redirect(url_for("auth.login"))

    # Create auth token and set cookie
    auth_token = token_service.create_auth_token(user)
    response = make_response(redirect(redirect_url))
    response.set_cookie(
        "gk_session",
        auth_token,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
        max_age=86400,
    )

    _audit_log("login", user.username, "Magic link verified")

    return response


@bp.route("/logout", methods=["POST"])
def logout() -> Response:
    """Clear the auth cookie."""
    response = make_response(redirect(url_for("auth.login")))
    response.delete_cookie("gk_session")

    if hasattr(g, "user") and g.user:
        _audit_log("logout", g.user.username)

    return response


@bp.before_app_request
def load_user() -> None:
    """Load the current user from the auth cookie on every request."""
    g.user = None
    token = request.cookies.get("gk_session")
    if token:
        g.user = token_service.verify_auth_token(token)


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: require authentication."""
    from functools import wraps

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if g.get("user") is None:
            if _is_htmx():
                return "", 401
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)

    return decorated


def admin_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: require admin group membership."""
    from functools import wraps

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if g.get("user") is None:
            if _is_htmx():
                return "", 401
            return redirect(url_for("auth.login", next=request.url))
        if not Group.user_in_group(g.user.username, "admin"):
            abort(403)
        return f(*args, **kwargs)

    return decorated
