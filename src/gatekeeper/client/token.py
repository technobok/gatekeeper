"""Shared token signing/verification logic (no Flask dependency)."""

import time
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

TOKEN_VERSION = 1
AUTH_TOKEN_SALT = "gatekeeper-auth"
MAGIC_LINK_SALT = "gatekeeper-magic-link"


def create_serializer(secret_key: str) -> URLSafeTimedSerializer:
    """Create a URLSafeTimedSerializer with the given secret key."""
    return URLSafeTimedSerializer(secret_key)


def create_auth_token(
    secret_key: str,
    username: str,
    login_salt: str,
    app_salt: str,
    lifetime_seconds: int = 86400,
) -> str:
    """Create a signed authentication token."""
    expiry = int(time.time()) + lifetime_seconds
    payload = {
        "v": TOKEN_VERSION,
        "u": username,
        "e": expiry,
        "us": login_salt,
        "as": app_salt,
    }
    s = create_serializer(secret_key)
    return s.dumps(payload, salt=AUTH_TOKEN_SALT)


def decode_auth_token(secret_key: str, token: str) -> dict[str, Any] | None:
    """Decode a signed authentication token without full verification.

    Returns the payload dict if the signature is valid, None otherwise.
    Does NOT check user existence, salts, or enablement - that's the caller's job.
    """
    s = create_serializer(secret_key)
    try:
        payload = s.loads(token, salt=AUTH_TOKEN_SALT)
    except (BadSignature, SignatureExpired):
        return None

    if payload.get("v") != TOKEN_VERSION:
        return None

    if payload.get("e", 0) < time.time():
        return None

    return payload


def create_magic_link_token(
    secret_key: str,
    identifier: str,
    redirect_url: str = "/",
) -> str:
    """Create a magic link token."""
    payload = {
        "u": identifier,
        "r": redirect_url,
    }
    s = create_serializer(secret_key)
    return s.dumps(payload, salt=MAGIC_LINK_SALT)


def decode_magic_link_token(
    secret_key: str,
    token: str,
    max_age: int = 3600,
) -> dict[str, Any] | None:
    """Decode a magic link token.

    Returns payload dict with 'u' (username) and 'r' (redirect_url), or None.
    """
    s = create_serializer(secret_key)
    try:
        payload = s.loads(token, salt=MAGIC_LINK_SALT, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
    return payload
