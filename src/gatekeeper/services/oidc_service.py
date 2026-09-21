"""OIDC client.

Gatekeeper authenticates against the provider itself rather than trusting headers
from a proxy. That removes the header as an attack surface entirely: there is
nothing to forge, because nothing is trusted.

The security-critical parts — state, nonce, PKCE, signature validation, issuer
and audience checks, JWKS fetching and key rotation — belong to authlib. This
module decides *whether* to start a login and what to do with the claims.
"""

from __future__ import annotations

import logging
from typing import Any

from authlib.integrations.flask_client import OAuth
from flask import Flask, session, url_for

logger = logging.getLogger(__name__)

_CLIENT_NAME = "sso"

# Where the login page sends the user back to, carried across the round trip.
# Gatekeeper can percent-encode, so these travel as ordinary parameters and need
# no cookie -- which is the whole reason the proxy needed one.
_RETURN_KEYS = ("app_name", "callback_url", "next")

_oauth: OAuth | None = None


def init_app(app: Flask) -> None:
    """Attach the OAuth registry. Clients are registered lazily, per request."""
    global _oauth
    _oauth = OAuth(app)


def _setting(key: str) -> Any:
    from gatekeeper.blueprints.auth import _live_setting

    return _live_setting(key)


def is_configured() -> bool:
    """True when there is enough configuration to attempt a login."""
    return bool(
        str(_setting("oidc.issuer")).strip()
        and str(_setting("oidc.client_id")).strip()
        and str(_setting("oidc.client_secret")).strip()
    )


def provider_name() -> str:
    return str(_setting("oidc.provider_name")).strip() or "single sign-on"


def should_attempt() -> bool:
    """Whether single sign-on applies to this request.

    On means on, for everyone. There is deliberately no internal/external split:
    the external forwarder reaches us from a 10.* address like everything else,
    so the two cannot be told apart reliably, and a switch that cannot be trusted
    to mean what it says is worse than not having one.

    Answers only the policy question. Whether the attempt then succeeds is a
    separate matter, and failing is expected to be survivable.
    """
    if str(_setting("sso.mode")).strip().lower() != "oidc":
        return False
    if not is_configured():
        logger.warning("sso.mode is oidc but the client is not fully configured")
        return False
    return True


def _client() -> Any:
    """Build the client from current settings.

    Registered per request rather than once at startup, because the settings are
    editable in the admin page and a restart to pick them up would be a poor
    experience -- and a worse one to debug.
    """
    if _oauth is None:
        raise RuntimeError("OIDC support was not initialised")

    issuer = str(_setting("oidc.issuer")).strip().rstrip("/")
    name = f"{_CLIENT_NAME}_{abs(hash((issuer, str(_setting('oidc.client_id')))))}"

    existing = getattr(_oauth, name, None)
    if existing is not None:
        return existing

    _oauth.register(
        name=name,
        client_id=str(_setting("oidc.client_id")).strip(),
        client_secret=str(_setting("oidc.client_secret")).strip(),
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        client_kwargs={
            "scope": str(_setting("oidc.scopes")).strip() or "openid email profile",
            # Defence in depth: the secret already authenticates us, but PKCE
            # costs nothing and closes code interception.
            "code_challenge_method": "S256",
        },
    )
    return getattr(_oauth, name)


def derived_callback_url() -> str:
    """Where this service actually receives the callback.

    Built from the request so it is correct behind the reverse proxy and its path
    prefix; ProxyFix and `url_for(_external=True)` already carry the magic-link
    URLs, so the same machinery is doing the same job here.
    """
    return url_for("auth.sso_callback", _external=True)


def callback_url() -> str:
    """The redirect URI to send to the provider.

    Usually the address above, but overridable, because the provider will only
    accept a URI registered with it and that registration is often not ours to
    change. Pointing this at a path the reverse proxy forwards here lets an
    existing registration keep working -- which is exactly the situation left
    behind when a proxy that owned the old URI is retired.

    The same value must be used for the authorization request and the token
    exchange, which is why both go through here.
    """
    override = str(_setting("oidc.redirect_uri")).strip()
    return override or derived_callback_url()


def begin(return_params: dict[str, str]) -> Any:
    """Start a login, remembering where to send the user afterwards."""
    session["sso_return"] = {k: v for k, v in return_params.items() if k in _RETURN_KEYS and v}
    return _client().authorize_redirect(callback_url())


def complete() -> tuple[dict[str, Any] | None, dict[str, str]]:
    """Finish a login.

    Returns (claims, return_params). Claims are None when the exchange or
    validation failed; the caller falls back to the form rather than showing an
    error page, because a provider being unreachable should not lock anyone out.
    """
    return_params = dict(session.pop("sso_return", {}) or {})
    try:
        token = _client().authorize_access_token()
    except Exception as exc:
        logger.warning(f"OIDC token exchange failed: {exc}")
        return None, return_params

    claims = token.get("userinfo") or {}
    if not claims:
        logger.warning("OIDC token carried no claims")
        return None, return_params

    return dict(claims), return_params


def claim_email(claims: dict[str, Any]) -> str:
    """The address to resolve on, preferring a verified mailbox over a sign-in name."""
    for key in ("email", "preferred_username", "upn"):
        value = str(claims.get(key) or "").strip()
        if "@" in value:
            return value
    return ""


def claim_upn(claims: dict[str, Any]) -> str:
    """The sign-in name the provider asserts."""
    for key in ("preferred_username", "upn", "email"):
        value = str(claims.get(key) or "").strip()
        if value:
            return value
    return ""


def claim_fullname(claims: dict[str, Any]) -> str:
    """A display name, if the provider offers one.

    `name` is a standard OIDC claim, unlike the proxy's `X-Auth-Request-User`,
    which carried the opaque subject and was no use as a name at all.
    """
    name = str(claims.get("name") or "").strip()
    if name:
        return name
    given = str(claims.get("given_name") or "").strip()
    family = str(claims.get("family_name") or "").strip()
    return " ".join(p for p in (given, family) if p)


def describe() -> dict[str, Any]:
    """Current state, for the admin page and the diagnostic."""
    return {
        "mode": str(_setting("sso.mode")),
        "configured": is_configured(),
        "issuer": str(_setting("oidc.issuer")),
        "client_id": str(_setting("oidc.client_id")),
        "secret_set": bool(str(_setting("oidc.client_secret")).strip()),
        "scopes": str(_setting("oidc.scopes")),
        "provider_name": provider_name(),
        "redirect_uri": str(_setting("oidc.redirect_uri")),
        # Shown in full: this is an admin-only page and an administrator needs to
        # be able to check the value against the provider, not just be told that
        # something is set.
        "client_secret": str(_setting("oidc.client_secret")),
    }
