"""GatekeeperClient facade - unified API for both local and HTTP modes."""

from gatekeeper_client.models import User
from gatekeeper_client.token import create_auth_token, decode_auth_token, decode_magic_link_token


class GatekeeperClient:
    """Main client for Gatekeeper authentication.

    Supports two modes:
    - Local mode: direct SQLite access (requires apsw)
    - HTTP mode: remote API calls (requires httpx)

    Usage:
        # Local mode
        gk = GatekeeperClient(secret_key="...", db_path="/path/to/gatekeeper.sqlite3")

        # HTTP mode
        gk = GatekeeperClient(secret_key="...", server_url="https://auth.example.com", api_key="gk_...")

        # Verify a token
        user = gk.authenticate(cookie_value)

        # Flask integration
        gk.init_app(app, cookie_name="gk_session")
    """

    def __init__(
        self,
        secret_key: str,
        db_path: str | None = None,
        server_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.secret_key = secret_key

        if db_path:
            from gatekeeper_client.backends.local import LocalBackend

            self.backend = LocalBackend(db_path)
            self.mode = "local"
        elif server_url and api_key:
            from gatekeeper_client.backends.http import HttpBackend

            self.backend = HttpBackend(server_url, api_key)
            self.mode = "http"
        else:
            raise ValueError(
                "Provide either db_path (local mode) or server_url + api_key (HTTP mode)"
            )

        self._flask_app = None
        self._cookie_name = "gk_session"

    def authenticate(self, cookie_value: str) -> User | None:
        """Verify an auth token from a cookie and return the User if valid."""
        payload = decode_auth_token(self.secret_key, cookie_value)
        if payload is None:
            return None

        username = payload.get("u")
        if not username:
            return None

        user = self.backend.get_user(username)
        if user is None or not user.enabled:
            return None

        # Verify login_salt
        if self.mode == "local":
            from gatekeeper_client.backends.local import LocalBackend

            assert isinstance(self.backend, LocalBackend)
            login_salt = self.backend.get_user_login_salt(username)
            if login_salt != payload.get("us"):
                return None
        # In HTTP mode, we trust the server's user data

        # Verify app_salt
        app_salt = self.backend.get_app_salt()
        if app_salt != payload.get("as"):
            return None

        # Attach groups if not already present
        if user.groups is None:
            user.groups = self.backend.get_user_groups(username)

        return user

    def verify_magic_link(self, token: str, max_age: int = 3600) -> tuple[User, str] | None:
        """Verify a magic link token. Returns (User, redirect_url) or None."""
        payload = decode_magic_link_token(self.secret_key, token, max_age=max_age)
        if payload is None:
            return None

        username = payload.get("u")
        redirect_url = payload.get("r", "/")

        if not username:
            return None

        user = self.backend.get_user(username)
        if user is None or not user.enabled:
            return None

        return user, redirect_url

    def create_auth_token(self, user: User, lifetime_seconds: int = 86400) -> str:
        """Create a signed auth token for a user."""
        if self.mode == "local":
            from gatekeeper_client.backends.local import LocalBackend

            assert isinstance(self.backend, LocalBackend)
            login_salt = self.backend.get_user_login_salt(user.username) or ""
            app_salt = self.backend.get_app_salt()
            return create_auth_token(
                self.secret_key, user.username, login_salt, app_salt, lifetime_seconds
            )
        else:
            # HTTP mode: ask the server to create the token
            from gatekeeper_client.backends.http import HttpBackend

            assert isinstance(self.backend, HttpBackend)
            token = self.backend.create_token(user.username, lifetime_seconds)
            if token is None:
                raise RuntimeError(f"Server failed to create token for {user.username}")
            return token

    def send_magic_link(
        self,
        identifier: str,
        callback_url: str,
        redirect_url: str = "/",
    ) -> bool:
        """Resolve an identifier and send a magic link email."""
        user = self.backend.resolve_identifier(identifier)
        if user is None:
            return False
        return self.backend.send_magic_link_email(user, callback_url, redirect_url)

    def get_user(self, username: str) -> User | None:
        """Look up a user by username."""
        return self.backend.get_user(username)

    def get_user_groups(self, username: str) -> list[str]:
        """Get group names for a user."""
        return self.backend.get_user_groups(username)

    # Flask integration methods

    def init_app(self, app, cookie_name: str = "gk_session") -> None:
        """Initialize Flask integration. Sets up before_request hook."""
        from gatekeeper_client.flask_integration import setup_flask_integration

        self._flask_app = app
        self._cookie_name = cookie_name
        setup_flask_integration(app, self, cookie_name)

    def login_required(self, f):
        """Decorator: require authentication."""
        from gatekeeper_client.flask_integration import login_required_decorator

        return login_required_decorator(self, f)

    def group_required(self, group_name: str):
        """Decorator: require group membership."""
        from gatekeeper_client.flask_integration import group_required_decorator

        return group_required_decorator(self, group_name)
