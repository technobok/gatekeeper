"""GatekeeperClient facade - unified API for both local and HTTP modes."""

from gatekeeper_client.models import Group, User
from gatekeeper_client.token import create_auth_token, decode_auth_token, decode_magic_link_token


class GatekeeperClient:
    """Main client for Gatekeeper authentication.

    Supports two modes:
    - Local mode: direct SQLite access (requires apsw)
    - HTTP mode: remote API calls (requires httpx)

    Usage:
        # Local mode (secret_key auto-read from database)
        gk = GatekeeperClient(db_path="/path/to/gatekeeper.sqlite3")

        # HTTP mode
        gk = GatekeeperClient(secret_key="...", server_url="https://auth.example.com", api_key="gk_...")

        # Verify a token
        user = gk.authenticate(cookie_value)

        # Flask integration
        gk.init_app(app, cookie_name="gk_session")
    """

    def __init__(
        self,
        secret_key: str | None = None,
        db_path: str | None = None,
        server_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        if db_path:
            from gatekeeper_client.backends.local import LocalBackend

            self.backend = LocalBackend(db_path)
            # Auto-read secret_key from database if not provided
            self.secret_key = secret_key or self.backend.get_secret_key()
            self.mode = "local"
        elif server_url and api_key:
            from gatekeeper_client.backends.http import HttpBackend

            self.backend = HttpBackend(server_url, api_key)
            self.secret_key = secret_key
            self.mode = "http"
        else:
            raise ValueError(
                "Provide either db_path (local mode) or server_url + api_key (HTTP mode)"
            )

        self._flask_app = None
        self._cookie_name = "gk_session"

    # -------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------

    def authenticate(self, cookie_value: str) -> User | None:
        """Verify an auth token from a cookie and return the User if valid."""
        # In HTTP mode without secret_key, verify via API
        if self.mode == "http" and not self.secret_key:
            from gatekeeper_client.backends.http import HttpBackend

            assert isinstance(self.backend, HttpBackend)
            return self.backend.verify_token(cookie_value)

        # Local verification requires secret_key
        if not self.secret_key:
            return None

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
        # In HTTP mode with secret_key, we trust the server's user data

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
        # In HTTP mode without secret_key, verify via API
        if self.mode == "http" and not self.secret_key:
            from gatekeeper_client.backends.http import HttpBackend

            assert isinstance(self.backend, HttpBackend)
            return self.backend.verify_magic_link(token)

        # Local verification requires secret_key
        if not self.secret_key:
            return None

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
            assert self.secret_key is not None  # Required for local mode
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
        app_name: str | None = None,
    ) -> bool:
        """Resolve an identifier and send a magic link email."""
        user = self.backend.resolve_identifier(identifier)
        if user is None:
            return False
        return self.backend.send_magic_link_email(
            user, callback_url, redirect_url, app_name=app_name
        )

    def resolve_identifier(self, identifier: str) -> User | None:
        """Resolve a login identifier (email, domain\\user, or username) to a User.

        In local mode with LDAP enabled, this will also search LDAP and
        auto-provision users found there.
        """
        return self.backend.resolve_identifier(identifier)

    # -------------------------------------------------------------------
    # User management
    # -------------------------------------------------------------------

    def get_user(self, username: str) -> User | None:
        """Look up a user by username."""
        return self.backend.get_user(username)

    def get_user_groups(self, username: str) -> list[str]:
        """Get group names for a user."""
        return self.backend.get_user_groups(username)

    def create_user(
        self,
        username: str,
        email: str,
        fullname: str = "",
        enabled: bool = True,
    ) -> User | None:
        """Create a new user."""
        return self.backend.create_user(username, email, fullname, enabled)

    def update_user(
        self,
        username: str,
        email: str | None = None,
        fullname: str | None = None,
        enabled: bool | None = None,
    ) -> User | None:
        """Update a user's fields. Returns updated User or None if not found."""
        return self.backend.update_user(username, email, fullname, enabled)

    def delete_user(self, username: str) -> bool:
        """Delete a user and all their group memberships."""
        return self.backend.delete_user(username)

    def list_users(
        self,
        search: str | None = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[User]:
        """List users with optional filtering."""
        return self.backend.list_users(search, enabled_only, limit, offset)

    def count_users(self, enabled_only: bool = False) -> int:
        """Count users."""
        return self.backend.count_users(enabled_only)

    def rotate_user_salt(self, username: str) -> str | None:
        """Rotate a user's login salt, invalidating their sessions."""
        return self.backend.rotate_user_salt(username)

    # -------------------------------------------------------------------
    # User properties
    # -------------------------------------------------------------------

    def get_user_properties(self, username: str, app: str) -> dict[str, str | None]:
        """Get all properties for a user+app."""
        return self.backend.get_user_properties(username, app)

    def get_user_property(self, username: str, app: str, key: str) -> str | None:
        """Get a single property value."""
        return self.backend.get_user_property(username, app, key)

    def set_user_properties(
        self, username: str, app: str, properties: dict[str, str | None]
    ) -> dict[str, str | None]:
        """Bulk upsert properties. Returns the properties dict."""
        return self.backend.set_user_properties(username, app, properties)

    def set_user_property(
        self, username: str, app: str, key: str, value: str | None
    ) -> None:
        """Set a single property."""
        self.backend.set_user_property(username, app, key, value)

    def delete_user_property(self, username: str, app: str, key: str) -> bool:
        """Delete a single property."""
        return self.backend.delete_user_property(username, app, key)

    def delete_user_properties(self, username: str, app: str) -> int:
        """Delete all properties for a user+app."""
        return self.backend.delete_user_properties(username, app)

    # -------------------------------------------------------------------
    # Group management
    # -------------------------------------------------------------------

    def get_group(self, name: str) -> Group | None:
        """Look up a group by name."""
        return self.backend.get_group(name)

    def create_group(self, name: str, description: str = "") -> Group | None:
        """Create a new group."""
        return self.backend.create_group(name, description)

    def update_group(self, name: str, description: str) -> Group | None:
        """Update a group's description."""
        return self.backend.update_group(name, description)

    def delete_group(self, name: str) -> bool:
        """Delete a group and all its memberships."""
        return self.backend.delete_group(name)

    def list_groups(self) -> list[Group]:
        """List all groups."""
        return self.backend.list_groups()

    def get_group_members(self, name: str) -> list[str]:
        """Get usernames of all members in a group."""
        return self.backend.get_group_members(name)

    def add_group_member(self, group_name: str, username: str) -> bool:
        """Add a user to a group. Returns False if already a member."""
        return self.backend.add_group_member(group_name, username)

    def remove_group_member(self, group_name: str, username: str) -> bool:
        """Remove a user from a group."""
        return self.backend.remove_group_member(group_name, username)

    # -------------------------------------------------------------------
    # System
    # -------------------------------------------------------------------

    def rotate_app_salt(self) -> str:
        """Rotate the global app salt, invalidating all sessions."""
        return self.backend.rotate_app_salt()

    # -------------------------------------------------------------------
    # Flask integration
    # -------------------------------------------------------------------

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
