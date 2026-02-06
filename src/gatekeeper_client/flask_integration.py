"""Flask integration helpers for GatekeeperClient."""

import logging
from functools import wraps

from flask import g, redirect, request, url_for

logger = logging.getLogger("gatekeeper_client.flask")


def setup_flask_integration(app, client, cookie_name: str = "gk_session") -> None:
    """Set up before_request hook to authenticate users from cookie."""

    @app.before_request
    def _load_user():
        g.user = None
        token = request.cookies.get(cookie_name)
        if token:
            try:
                g.user = client.authenticate(token)
            except Exception as e:
                logger.error(f"Authentication error: {e}")


def login_required_decorator(client, f):
    """Decorator that redirects to login if not authenticated."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def group_required_decorator(client, group_name: str):
    """Decorator factory that requires group membership."""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = g.get("user")
            if user is None:
                return redirect(url_for("auth.login", next=request.url))
            if not user.in_group(group_name):
                from flask import abort

                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator
