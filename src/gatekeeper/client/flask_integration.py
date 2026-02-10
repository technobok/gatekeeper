"""Flask integration helpers for GatekeeperClient."""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any

from flask import Flask, g, redirect, request, url_for

if TYPE_CHECKING:
    from gatekeeper.client.client import GatekeeperClient

logger = logging.getLogger("gatekeeper.client.flask")


def setup_flask_integration(
    app: Flask, client: GatekeeperClient, cookie_name: str = "gk_session"
) -> None:
    """Set up before_request hook to authenticate users from cookie."""

    @app.before_request
    def _load_user() -> None:
        g.user = None
        token = request.cookies.get(cookie_name)
        if token:
            try:
                g.user = client.authenticate(token)
            except Exception as e:
                logger.error(f"Authentication error: {e}")


def login_required_decorator(client: GatekeeperClient, f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that redirects to login if not authenticated."""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if g.get("user") is None:
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def group_required_decorator(
    client: GatekeeperClient, group_name: str
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory that requires group membership."""

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            user = g.get("user")
            if user is None:
                return redirect(url_for("auth.login", next=request.url))
            if not user.in_group(group_name):
                from flask import abort

                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator
