"""Authentication blueprint - login/verify/logout (HTMX)."""

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

from gatekeeper.db import get_db
from gatekeeper.models.group import Group
from gatekeeper.models.user import User
from gatekeeper.services import email_service, token_service

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
        return _auto_provision(ldap_user.username, ldap_user.email, ldap_user.fullname)
    return None


def _try_ldap_domain(domain: str, username: str) -> User | None:
    """Try LDAP lookup for a specific domain, auto-provisioning if found."""
    from gatekeeper.services.ldap_service import is_ldap_enabled, lookup_by_username

    if not is_ldap_enabled():
        return None

    ldap_user = lookup_by_username(domain, username)
    if ldap_user:
        return _auto_provision(ldap_user.username, ldap_user.email, ldap_user.fullname)
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
            return _auto_provision(ldap_user.username, ldap_user.email, ldap_user.fullname)
    return None


def _auto_provision(username: str, email: str, fullname: str) -> User:
    """Auto-create a user from LDAP data and add to standard group."""
    user = User.get(username)
    if user:
        return user

    user = User.create(username=username, email=email, fullname=fullname)
    group = Group.get("standard")
    if group:
        group.add_member(username)

    current_app.logger.info(f"Auto-provisioned LDAP user: {username} ({email})")
    _audit_log("auto_provision", username, f"LDAP auto-provisioned: {email}")
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
def login():
    """Show login form or process login request."""
    if request.method == "GET":
        return render_template("auth/login.html", next_url=request.args.get("next", "/"))

    identifier = request.form.get("identifier", "").strip()
    next_url = request.form.get("next", "/")

    user, error = _resolve_identifier(identifier)
    if error:
        flash(error, "error")
        if _is_htmx():
            return render_template("auth/login.html", next_url=next_url, identifier=identifier)
        return redirect(url_for("auth.login", next=next_url))

    # Only admin users may log in
    if not Group.user_in_group(user.username, "admin"):
        flash("Access is restricted to administrators.", "error")
        _audit_log("login_rejected", user.username, "Non-admin login attempt")
        if _is_htmx():
            return render_template("auth/login.html", next_url=next_url, identifier=identifier)
        return redirect(url_for("auth.login", next=next_url))

    # Create magic link token and send email
    magic_token = token_service.create_magic_link_token(user.username, redirect_url=next_url)
    callback_url = url_for("auth.verify", token=magic_token, _external=True)

    sent = email_service.send_magic_link(user.email, callback_url)
    if not sent:
        flash("Failed to send login email. Please try again.", "error")
        if _is_htmx():
            return render_template("auth/login.html", next_url=next_url, identifier=identifier)
        return redirect(url_for("auth.login", next=next_url))

    _audit_log("magic_link_sent", user.username, f"Email sent to {user.email}")

    return render_template("auth/login_sent.html", email=user.email)


@bp.route("/verify")
def verify():
    """Verify a magic link token and set the auth cookie."""
    token = request.args.get("token")
    if not token:
        abort(400)

    result = token_service.verify_magic_link_token(token)
    if result is None:
        flash("This login link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("auth.login"))

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
def logout():
    """Clear the auth cookie."""
    response = make_response(redirect(url_for("auth.login")))
    response.delete_cookie("gk_session")

    if hasattr(g, "user") and g.user:
        _audit_log("logout", g.user.username)

    return response


@bp.before_app_request
def load_user():
    """Load the current user from the auth cookie on every request."""
    g.user = None
    token = request.cookies.get("gk_session")
    if token:
        g.user = token_service.verify_auth_token(token)


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def login_required(f):
    """Decorator: require authentication."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if g.get("user") is None:
            if _is_htmx():
                return "", 401
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """Decorator: require admin group membership."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if g.get("user") is None:
            if _is_htmx():
                return "", 401
            return redirect(url_for("auth.login", next=request.url))
        if not Group.user_in_group(g.user.username, "admin"):
            abort(403)
        return f(*args, **kwargs)

    return decorated
