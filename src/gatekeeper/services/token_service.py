"""Signed token creation and verification."""

import time

from flask import current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from gatekeeper.models.app_setting import AppSetting
from gatekeeper.models.user import User

TOKEN_VERSION = 1
MAGIC_LINK_SALT = "gatekeeper-magic-link"
AUTH_TOKEN_SALT = "gatekeeper-auth"


def get_serializer() -> URLSafeTimedSerializer:
    """Get a URLSafeTimedSerializer using the app's SECRET_KEY."""
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def create_auth_token(user: User, lifetime_seconds: int = 86400) -> str:
    """Create a signed authentication token for a user.

    The token embeds the user's login_salt and the app_salt at creation time,
    allowing invalidation by rotating either salt.
    """
    app_salt = AppSetting.get_app_salt()
    expiry = int(time.time()) + lifetime_seconds

    payload = {
        "v": TOKEN_VERSION,
        "u": user.username,
        "e": expiry,
        "us": user.login_salt,
        "as": app_salt,
    }

    s = get_serializer()
    return s.dumps(payload, salt=AUTH_TOKEN_SALT)


def verify_auth_token(token: str) -> User | None:
    """Verify a signed authentication token.

    Checks: signature -> expiry -> user exists -> user enabled ->
    login_salt matches -> app_salt matches.

    Returns the User if valid, None otherwise.
    """
    s = get_serializer()

    try:
        payload = s.loads(token, salt=AUTH_TOKEN_SALT)
    except (BadSignature, SignatureExpired):
        return None

    # Check version
    if payload.get("v") != TOKEN_VERSION:
        return None

    # Check expiry
    if payload.get("e", 0) < time.time():
        return None

    # Look up user
    username = payload.get("u")
    if not username:
        return None

    user = User.get(username)
    if user is None or not user.enabled:
        return None

    # Check login_salt matches (user-level invalidation)
    if payload.get("us") != user.login_salt:
        return None

    # Check app_salt matches (global invalidation)
    app_salt = AppSetting.get_app_salt()
    if payload.get("as") != app_salt:
        return None

    return user


def create_magic_link_token(
    identifier: str, redirect_url: str = "/", lifetime_seconds: int | None = None
) -> str:
    """Create a magic link token for passwordless login.

    Args:
        identifier: The resolved username.
        redirect_url: URL to redirect to after login.
        lifetime_seconds: Override expiry (defaults to config MAGIC_LINK_EXPIRY_SECONDS).
    """
    if lifetime_seconds is None:
        lifetime_seconds = current_app.config.get("MAGIC_LINK_EXPIRY_SECONDS", 3600)

    payload = {
        "u": identifier,
        "r": redirect_url,
    }

    s = get_serializer()
    return s.dumps(payload, salt=MAGIC_LINK_SALT)


def verify_magic_link_token(token: str) -> tuple[User, str] | None:
    """Verify a magic link token.

    Returns (User, redirect_url) if valid, None otherwise.
    """
    s = get_serializer()
    max_age = current_app.config.get("MAGIC_LINK_EXPIRY_SECONDS", 3600)

    try:
        payload = s.loads(token, salt=MAGIC_LINK_SALT, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None

    username = payload.get("u")
    redirect_url = payload.get("r", "/")

    if not username:
        return None

    user = User.get(username)
    if user is None or not user.enabled:
        return None

    return user, redirect_url
