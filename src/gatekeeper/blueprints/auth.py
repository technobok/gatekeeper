"""Authentication blueprint - login/verify/logout (HTMX)."""

import logging
from collections.abc import Callable, Sequence
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
from gatekeeper.models.app_setting import AppSetting
from gatekeeper.models.group import Group
from gatekeeper.models.user import User
from gatekeeper.services import email_service, token_service

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/auth")

# Set by the reverse proxy when it sees a logout, and cleared here after one
# request. Under SSO the identity headers would otherwise sign the user straight
# back in, making the logout button appear to do nothing.
SIGNED_OUT_COOKIE = "entra_signedout"

# Set when a single sign-on attempt fails, and honoured exactly once.
#
# Without it the login page is a trap: it redirects to the provider, the attempt
# fails, the user is returned here, and it redirects again. A one-shot marker
# turns an unbreakable loop into a form with an explanation on it.
SSO_FAILED_COOKIE = "sso_failed"


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
    from gatekeeper.services.ldap_service import LdapUser, resolve_domain

    assert isinstance(ldap_user, LdapUser)
    username = ldap_user.username
    user = User.get(username)
    if user:
        return user

    # Extract domain from username (DOMAIN\sam) and resolve to config casing
    raw_domain = username.split("\\", 1)[0] if "\\" in username else ""
    ldap_domain = resolve_domain(raw_domain) or raw_domain

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
        upn=ldap_user.upn,
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


def _live_setting(key: str) -> str | int | bool | list[str]:
    """Read a config value straight from the database.

    Deliberately bypasses ``app.config``, which is only populated at startup.
    The Entra switch has to take effect on the very next request, so that it can
    be used to turn the feature off in a hurry without bouncing the container.
    """
    from gatekeeper.config import parse_value, resolve_entry

    entry = resolve_entry(key)
    if entry is None:
        raise KeyError(f"Unknown config key: {key}")

    raw = AppSetting.get(key)
    return entry.default if raw is None else parse_value(entry, raw)


def _identifier_candidates(email: str, upn: str, ldap_domains: Sequence[str] = ()) -> list[str]:
    """Identifiers to try, in order, for a proxy-authenticated user.

    Nothing in the token carries the AD domain. Entra sends the routable UPN, so
    a tenant signing in as ``someone@company.com`` while the directory knows them
    as ``CORP\\someone`` gives no hint that ``CORP`` exists. But Gatekeeper is
    already told, in ``ldap.domains``, so each configured domain is paired with
    the sign-in name: ``pawe@demant.com`` with domain ``ASIAP`` yields
    ``asiap\\pawe``. These come first, being drawn from configuration rather than
    guessed.

    Next is the same form derived from the UPN's own domain label, which suits a
    tenant whose UPN domain does match the directory. It fails safe when it does
    not: a wrong guess matches nothing and the address is tried next.

    The address comes after both, because it is not a key -- several accounts can
    share one, and when they do there is nothing to choose between them.

    Deliberately not derived from the email address alone. An address whose local
    part happens to look like an account name would send an LDAP lookup after a
    name nobody has claimed, and ``_resolve_identifier`` auto-provisions whatever
    LDAP returns -- inventing an account from a guess.
    """
    candidates: list[str] = []

    def add(value: str) -> None:
        if value and value.lower() not in [c.lower() for c in candidates]:
            candidates.append(value)

    sign_in_name = (upn or email).partition("@")[0]
    for domain in ldap_domains:
        if domain and sign_in_name:
            add(f"{domain}\\{sign_in_name}")

    if "@" in upn:
        local, _, domain_part = upn.partition("@")
        first_label = domain_part.split(".", 1)[0]
        if local and first_label:
            add(f"{first_label}\\{local}")

    add(email)
    add(upn)

    return candidates


def _provision_entra_user(email: str, fullname: str) -> User | None:
    """Create a user from Entra claims, for someone in neither the DB nor LDAP."""
    username = email.split("@", 1)[0].lower()
    if not username:
        return None

    # A username collision means this local part belongs to somebody else --
    # the email lookup would have found them otherwise. Never take that account over.
    if User.get(username) is not None:
        logger.warning(f"Entra login for {email} collides with existing user {username}")
        return None

    user = User.create(username=username, email=email, fullname=fullname or username)

    group = Group.get("standard")
    if group:
        group.add_member(user.username)

    logger.info(f"Auto-provisioned Entra user: {user.username} ({email})")
    _audit_log("entra_provision", user.username, f"Entra auto-provisioned: {email}")
    return user


def _resolve_sso_user(email: str, upn: str, fullname: str = "") -> tuple[User | None, str | None]:
    """Resolve a user an identity provider has already authenticated.

    Shared by both single sign-on paths so they cannot drift apart: whichever way
    the claims arrived, the same rules decide which account they belong to.

    Returns (user, matched_on). A None user means no account could be resolved
    safely, and the caller should fall back to the form.
    """
    # Fast path. The UPN is what the provider actually asserts, and it is unique
    # and indexed, so a stamped account resolves in a single lookup -- no
    # derivation, no LDAP. Working out who someone is from an email address, for
    # a person just authenticated, is work that should need doing once at most.
    user = User.get_by_upn(upn)
    if user is not None:
        return user, f"upn:{upn}"

    # Slow path, for accounts not yet stamped. This is also the only path that
    # can reach LDAP.
    matched: str | None = None
    candidates = _identifier_candidates(email, upn, current_app.config.get("LDAP_DOMAINS", []))
    for identifier in candidates:
        user, _error = _resolve_identifier(identifier)
        if user is not None:
            matched = identifier
            break

    if user is not None:
        _stamp_upn(user, upn)
    elif email:
        # Only provision when the person genuinely has no account. Reaching here
        # with the address already in use means the lookup was ambiguous, not
        # empty -- _resolve_identifier refuses to choose between accounts sharing
        # an address, and rightly so. Provisioning then adds yet another account
        # with the same address, compounding the problem that blocked the match,
        # and hands the user an empty account carrying none of their groups.
        sharing = User.get_by_email(email)
        if sharing:
            logger.warning(
                f"Single sign-on for {email} matched no account, but the address is "
                f"already in use by {len(sharing)} accounts; refusing to provision. "
                f"Consolidate them, or sign in with a username."
            )
            flash(
                "Your email address matches more than one account. "
                "Please sign in with your username below.",
                "error",
            )
            return None, None

        user = _provision_entra_user(email, fullname)
        if user is not None:
            matched = "provisioned"
            _stamp_upn(user, upn)

    logger.info(
        f"Single sign-on resolution: email={email!r} upn={upn!r} "
        f"candidates={candidates!r} matched={matched!r} "
        f"user={user.username if user else None!r}"
    )
    return user, matched


def _stamp_upn(user: User, upn: str) -> None:
    """Record the UPN, and correct it when the provider now asserts another.

    Writing over an existing value is deliberate. Without it a UPN changed at the
    provider is never picked up: resolution falls back to the chain, matches the
    account, and then declines to fix the record -- while the stale value goes on
    occupying the unique index. The account has already been resolved by other
    means before we get here, and the ambiguity guard refuses to resolve an
    address held by more than one account, so this can only move a UPN onto the
    account it was already matched to.
    """
    if not upn or upn.lower() == (user.upn or "").lower():
        return

    previous = user.upn
    try:
        user.update(upn=upn)
        if previous:
            logger.info(f"Updated UPN for {user.username!r}: {previous!r} -> {upn!r}")
            _audit_log("sso_upn_changed", user.username, f"{previous} -> {upn}")
        else:
            logger.info(f"Recorded UPN {upn!r} against {user.username!r}")
    except Exception:
        logger.warning(
            f"Could not record UPN {upn!r} against {user.username!r}; "
            f"it is probably already held by another account"
        )


def _try_trusted_header_login(
    next_url: str, app_name: str, sso_callback_url: str
) -> Response | None:
    """Complete a login from proxy-supplied identity headers, when present.

    The older of the two single sign-on paths, kept until the OIDC one is proven.
    It trusts a header, which means anything able to reach this service directly
    can forge one -- which is exactly why it is going away.
    """
    if str(_live_setting("sso.mode")).strip().lower() == "oidc":
        return None
    if not _live_setting("auth.trusted_header_enabled"):
        return None

    email = request.headers.get(str(_live_setting("auth.trusted_header_email")), "").strip()
    if not email:
        return None

    upn = request.headers.get(str(_live_setting("auth.trusted_header_username")), "").strip()
    name_header = str(_live_setting("auth.trusted_header_name"))
    fullname = request.headers.get(name_header, "").strip() if name_header else ""

    user, matched = _resolve_sso_user(email, upn, fullname)
    if user is None:
        return None

    return _issue_sso_redirect(
        user, matched, next_url, app_name, sso_callback_url, source="entra_login"
    )


def _issue_sso_redirect(
    user: User,
    matched: str | None,
    next_url: str,
    app_name: str,
    sso_callback_url: str,
    source: str,
) -> Response | None:
    """Mint a magic-link token and hand the user to the calling application.

    Shared by both paths. From here the journey is the one the email form already
    takes, which is what keeps all eleven applications out of this entirely --
    they receive an ordinary magic-link callback and cannot tell the difference.
    """
    # Logging in to Gatekeeper itself stays admin-only, exactly as the form does.
    if not sso_callback_url and not Group.user_in_group(user.username, "admin"):
        _audit_log("login_rejected", user.username, "Non-admin single sign-on attempt")
        flash("Access is restricted to administrators.", "error")
        return None

    magic_token = token_service.create_magic_link_token(
        user.username,
        redirect_url=next_url or ("" if sso_callback_url else url_for("index")),
    )
    if sso_callback_url:
        sep = "&" if "?" in sso_callback_url else "?"
        verify_url = f"{sso_callback_url}{sep}token={magic_token}"
    else:
        verify_url = url_for("auth.verify", token=magic_token, _external=True)

    _audit_log(
        source,
        user.username,
        f"upn={user.upn or '-'} matched_on={matched or '-'} app={app_name or '-'}",
    )
    return redirect(verify_url)


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

        # Honour a just-signed-out marker exactly once. Otherwise logging out is
        # futile under SSO: the app clears its session, lands here, and the
        # identity headers sign the user straight back in without their asking.
        just_signed_out = bool(request.cookies.get(SIGNED_OUT_COOKIE))
        sso_failed = bool(request.cookies.get(SSO_FAILED_COOKIE))

        # An administrator's escape hatch, deliberately absent from the
        # interface. Someone the provider will not authenticate never comes back
        # to us to be offered a fallback, so the link has to be sendable.
        sso_declined = request.args.get("sso", "").lower() in ("off", "0", "no")

        if not (just_signed_out or sso_failed or sso_declined):
            # Pass the raw value, not the index fallback: with a callback_url the
            # destination belongs to the calling app, and an empty redirect leaves
            # the app to choose its own landing page. Sending someone to
            # Gatekeeper's index instead lands them on an admin-only page, which
            # bounces them back to this login form having actually signed in.
            entra_redirect = _try_trusted_header_login(
                request.args.get("next", ""), app_name, sso_callback_url
            )
            if entra_redirect is not None:
                return entra_redirect

            to_provider = _try_oidc_login(app_name, sso_callback_url)
            if to_provider is not None:
                return to_provider

        if just_signed_out:
            flash("You have been signed out.", "success")

        response = make_response(
            render_template(
                "auth/login.html",
                next_url=next_url,
                app_name=app_name,
                callback_url=sso_callback_url,
            )
        )
        if just_signed_out:
            response.delete_cookie(SIGNED_OUT_COOKIE, path="/")
        if sso_failed:
            response.delete_cookie(SSO_FAILED_COOKIE, path="/")
        return response

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


def _try_oidc_login(app_name: str, sso_callback_url: str) -> Response | None:
    """Start an OIDC login, if single sign-on applies to this request.

    Returns a redirect to the provider, or None to let the caller fall back to
    the form. Nothing here is fatal: a provider that cannot be reached must leave
    people able to log in by email, not locked out.
    """
    from gatekeeper.services import oidc_service

    if not oidc_service.should_attempt():
        return None

    try:
        return oidc_service.begin(
            {
                "app_name": app_name,
                "callback_url": sso_callback_url,
                "next": request.args.get("next", ""),
            }
        )
    except Exception as exc:
        logger.warning(f"Could not start an OIDC login: {exc}")
        return None


def _sso_failed(message: str, return_params: dict[str, str]) -> Response:
    """Send the user to the form, and stop trying until they act.

    The marker is what stops the login page bouncing them back to the provider
    the moment they arrive, which would be a loop with no way out.
    """
    flash(message, "error")
    target = url_for(
        "auth.login",
        app_name=return_params.get("app_name") or None,
        callback_url=return_params.get("callback_url") or None,
        next=return_params.get("next") or None,
    )
    response = redirect(target)
    response.set_cookie(
        SSO_FAILED_COOKIE,
        "1",
        max_age=120,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
    )
    return response


@bp.route("/sso/callback")
def sso_callback() -> Response:
    """Where the identity provider returns the user."""
    from gatekeeper.services import oidc_service

    claims, return_params = oidc_service.complete()
    if claims is None:
        return _sso_failed(
            f"Could not complete sign-in with {oidc_service.provider_name()}.", return_params
        )

    email = oidc_service.claim_email(claims)
    upn = oidc_service.claim_upn(claims)
    if not email and not upn:
        logger.warning("OIDC login carried neither an address nor a sign-in name")
        return _sso_failed("The sign-in did not include an email address.", return_params)

    user, matched = _resolve_sso_user(email, upn, oidc_service.claim_fullname(claims))
    if user is None:
        return _sso_failed(
            f"Your {oidc_service.provider_name()} account is not linked to an account here.",
            return_params,
        )

    issued = _issue_sso_redirect(
        user,
        matched,
        return_params.get("next", ""),
        return_params.get("app_name", ""),
        return_params.get("callback_url", ""),
        source="sso_login",
    )
    if issued is None:
        return _sso_failed("Access is restricted to administrators.", return_params)
    return issued


@bp.route("/whoami")
def whoami() -> Response:
    """Diagnostic: what the proxy sent, and how Gatekeeper resolves it.

    Read-only on purpose. The live login path lets ``_resolve_identifier`` fall
    back to LDAP, which auto-provisions whatever it finds; doing that here would
    mean a diagnostic page could create accounts. So this reports only what is
    already in the database, and says so.
    """
    email_header = str(_live_setting("auth.trusted_header_email"))
    upn_header = str(_live_setting("auth.trusted_header_username"))
    email = request.headers.get(email_header, "").strip()
    upn = request.headers.get(upn_header, "").strip()

    lines = [
        "Trusted header authentication",
        f"  enabled          {bool(_live_setting('auth.trusted_header_enabled'))}",
        f"  {email_header}  {email or '(not sent)'}",
        f"  {upn_header}  {upn or '(not sent)'}",
        "",
    ]

    if not email:
        lines += [
            "No identity headers arrived.",
            "",
            "Internally that is expected: they are only added for requests that go",
            "through the external authentication path.",
        ]
        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    stamped = User.get_by_upn(upn)
    if stamped is not None:
        lines += [
            f"Matched directly on UPN: {stamped.username}",
            "  One indexed lookup. No derivation, no LDAP.",
            "",
        ]
        groups = ", ".join(Group.get_groups_for_user(stamped.username)) or "(none)"
        lines += [
            f"  full name  {stamped.fullname or '(none)'}",
            f"  email      {stamped.email}",
            f"  enabled    {stamped.enabled}",
            f"  groups     {groups}",
        ]
        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    lines.append("No account carries this UPN yet, so it falls back to matching.")
    lines.append("A successful match records the UPN, and later logins skip this.")
    lines.append("")
    lines.append("Identifiers tried, in order:")
    matched = None
    domains = current_app.config.get("LDAP_DOMAINS", [])
    for n, identifier in enumerate(_identifier_candidates(email, upn, domains), start=1):
        if matched is not None:
            lines.append(f"  {n}. {identifier}  (not reached)")
            continue
        found = User.get(identifier) if "@" not in identifier else None
        if found is None and "@" in identifier:
            by_email = User.get_by_email(identifier)
            if len(by_email) > 1:
                lines.append(f"  {n}. {identifier}  AMBIGUOUS: {len(by_email)} accounts share it")
                continue
            found = by_email[0] if by_email else None
        if found is not None:
            matched = found
            lines.append(f"  {n}. {identifier}  MATCHED")
        else:
            lines.append(f"  {n}. {identifier}  no account")

    lines.append("")
    if matched is None:
        lines += [
            "No local account matched.",
            "A real login would next try LDAP, and provision an account only if the",
            "email address is not already in use.",
        ]
    else:
        groups = ", ".join(Group.get_groups_for_user(matched.username)) or "(none)"
        lines += [
            f"Resolves to: {matched.username}",
            f"  full name  {matched.fullname or '(none)'}",
            f"  email      {matched.email}",
            f"  enabled    {matched.enabled}",
            f"  groups     {groups}",
        ]

    return Response("\n".join(lines) + "\n", mimetype="text/plain")


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
