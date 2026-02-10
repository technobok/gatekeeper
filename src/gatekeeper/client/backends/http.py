"""HTTP API backend for GatekeeperClient (remote auth server)."""

import logging

import httpx

from gatekeeper.client.models import Group, User

logger = logging.getLogger("gatekeeper.client.http")


class HttpBackend:
    """Backend that communicates with a remote Gatekeeper server via JSON API."""

    def __init__(self, server_url: str, api_key: str, timeout: float = 10.0) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.server_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout,
        )

    # -------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------

    def get_user(self, username: str) -> User | None:
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/users/{username}")
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return None
                resp.raise_for_status()
                data = resp.json()
                groups_resp = client.get(f"/api/v1/users/{username}/groups")
                groups = (
                    groups_resp.json().get("groups", []) if groups_resp.status_code == 200 else []
                )
                return User(
                    username=data["username"],
                    email=data["email"],
                    fullname=data.get("fullname", ""),
                    enabled=data.get("enabled", True),
                    groups=groups,
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Gatekeeper API error getting user {username}: {e.response.status_code} - {e.response.text}"
            )
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting user {username} from Gatekeeper: {e}")
            return None

    def get_user_groups(self, username: str) -> list[str]:
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/users/{username}/groups")
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return []
                if resp.status_code != 200:
                    logger.warning(f"Failed to get groups for {username}: {resp.status_code}")
                    return []
                return resp.json().get("groups", [])
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting groups for {username}: {e}")
            return []

    def get_app_salt(self) -> str:
        try:
            with self._client() as client:
                resp = client.get("/api/v1/system/app-salt")
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return ""
                resp.raise_for_status()
                return resp.json()["app_salt"]
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return ""
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Gatekeeper API error getting app_salt: {e.response.status_code} - {e.response.text}"
            )
            return ""
        except Exception as e:
            logger.error(f"Unexpected error getting app_salt from Gatekeeper: {e}")
            return ""

    def get_login_url(self) -> str | None:
        """Return the server's login URL (derived from server_url)."""
        return f"{self.server_url}/auth/login"

    def get_group(self, name: str) -> Group | None:
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/groups/{name}")
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return None
                resp.raise_for_status()
                data = resp.json()
                members_resp = client.get(f"/api/v1/groups/{name}/members")
                members = (
                    members_resp.json().get("members", [])
                    if members_resp.status_code == 200
                    else []
                )
                return Group(
                    name=data["name"],
                    description=data.get("description", ""),
                    members=members,
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Gatekeeper API error getting group {name}: {e.response.status_code} - {e.response.text}"
            )
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting group {name}: {e}")
            return None

    # -------------------------------------------------------------------
    # Auth operations
    # -------------------------------------------------------------------

    def resolve_identifier(self, identifier: str) -> User | None:
        try:
            with self._client() as client:
                resp = client.post(
                    "/api/v1/auth/resolve",
                    json={"identifier": identifier},
                )
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return None
                if resp.status_code == 404:
                    logger.debug(f"User not found for identifier: {identifier}")
                    return None
                if resp.status_code != 200:
                    logger.warning(
                        f"Failed to resolve identifier {identifier}: {resp.status_code} - {resp.text}"
                    )
                    return None
                data = resp.json()
                return User(
                    username=data["username"],
                    email=data["email"],
                    fullname=data.get("fullname", ""),
                    enabled=data.get("enabled", True),
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error resolving identifier {identifier}: {e}")
            return None

    def send_magic_link_email(
        self, user: User, callback_url: str, redirect_url: str, app_name: str | None = None
    ) -> bool:
        try:
            with self._client() as client:
                payload = {
                    "identifier": user.username,
                    "callback_url": callback_url,
                    "redirect_url": redirect_url,
                }
                if app_name is not None:
                    payload["app_name"] = app_name
                resp = client.post(
                    "/api/v1/auth/send-magic-link",
                    json=payload,
                )
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return False
                if resp.status_code != 200:
                    logger.error(
                        f"Failed to send magic link for {user.username}: {resp.status_code} - {resp.text}"
                    )
                    return False
                return True
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending magic link for {user.username}: {e}")
            return False

    def verify_token(self, token: str) -> User | None:
        """Ask the server to verify a token (alternative to local verification)."""
        try:
            with self._client() as client:
                resp = client.post(
                    "/api/v1/auth/verify-token",
                    json={"token": token},
                )
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return None
                if resp.status_code != 200:
                    logger.debug(f"Token verification failed: {resp.status_code}")
                    return None
                data = resp.json()
                return User(
                    username=data["username"],
                    email=data["email"],
                    fullname=data.get("fullname", ""),
                    enabled=data.get("enabled", True),
                    groups=data.get("groups"),
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error verifying token: {e}")
            return None

    def create_token(self, username: str, lifetime_seconds: int = 86400) -> str | None:
        """Ask the server to create an auth token."""
        try:
            with self._client() as client:
                resp = client.post(
                    "/api/v1/auth/create-token",
                    json={"username": username, "lifetime_seconds": lifetime_seconds},
                )
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return None
                if resp.status_code != 200:
                    logger.error(
                        f"Failed to create token for {username}: {resp.status_code} - {resp.text}"
                    )
                    return None
                return resp.json()["token"]
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating token for {username}: {e}")
            return None

    def verify_magic_link(self, token: str) -> tuple[User, str] | None:
        """Ask the server to verify a magic link token."""
        try:
            with self._client() as client:
                resp = client.post(
                    "/api/v1/auth/verify-magic-link",
                    json={"token": token},
                )
                if resp.status_code == 401:
                    logger.error(
                        f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}"
                    )
                    return None
                if resp.status_code != 200:
                    logger.debug(f"Magic link verification failed: {resp.status_code}")
                    return None
                data = resp.json()
                user = User(
                    username=data["username"],
                    email=data["email"],
                    fullname=data.get("fullname", ""),
                    enabled=data.get("enabled", True),
                    groups=data.get("groups"),
                )
                return user, data.get("redirect_url", "/")
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error verifying magic link: {e}")
            return None

    # -------------------------------------------------------------------
    # User management
    # -------------------------------------------------------------------

    def create_user(
        self, username: str, email: str, fullname: str = "", enabled: bool = True
    ) -> User | None:
        """Create a new user via API."""
        try:
            with self._client() as client:
                resp = client.post(
                    "/api/v1/users",
                    json={
                        "username": username,
                        "email": email,
                        "fullname": fullname,
                        "enabled": enabled,
                    },
                )
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return None
                if resp.status_code == 409:
                    logger.error(f"User {username} already exists")
                    return None
                if resp.status_code != 201:
                    logger.error(
                        f"Failed to create user {username}: {resp.status_code} - {resp.text}"
                    )
                    return None
                data = resp.json()
                return User(
                    username=data["username"],
                    email=data["email"],
                    fullname=data.get("fullname", ""),
                    enabled=data.get("enabled", True),
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating user {username}: {e}")
            return None

    def update_user(
        self,
        username: str,
        email: str | None = None,
        fullname: str | None = None,
        enabled: bool | None = None,
    ) -> User | None:
        """Update a user via API."""
        payload = {}
        if email is not None:
            payload["email"] = email
        if fullname is not None:
            payload["fullname"] = fullname
        if enabled is not None:
            payload["enabled"] = enabled

        if not payload:
            return self.get_user(username)

        try:
            with self._client() as client:
                resp = client.patch(f"/api/v1/users/{username}", json=payload)
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return None
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
                return User(
                    username=data["username"],
                    email=data["email"],
                    fullname=data.get("fullname", ""),
                    enabled=data.get("enabled", True),
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error updating user {username}: {e}")
            return None

    def delete_user(self, username: str) -> bool:
        """Delete a user via API."""
        try:
            with self._client() as client:
                resp = client.delete(f"/api/v1/users/{username}")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return False
                if resp.status_code == 404:
                    return False
                resp.raise_for_status()
                return True
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting user {username}: {e}")
            return False

    def list_users(
        self,
        search: str | None = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[User]:
        """List users via API."""
        params: dict[str, str | int] = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search
        if enabled_only:
            params["enabled_only"] = "true"

        try:
            with self._client() as client:
                resp = client.get("/api/v1/users", params=params)
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return []
                resp.raise_for_status()
                data = resp.json()
                return [
                    User(
                        username=u["username"],
                        email=u["email"],
                        fullname=u.get("fullname", ""),
                        enabled=u.get("enabled", True),
                    )
                    for u in data.get("users", [])
                ]
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing users: {e}")
            return []

    def count_users(self, enabled_only: bool = False) -> int:
        """Count users via API (uses list endpoint with limit=0)."""
        params: dict[str, str | int] = {"limit": 0}
        if enabled_only:
            params["enabled_only"] = "true"

        try:
            with self._client() as client:
                resp = client.get("/api/v1/users", params=params)
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return 0
                resp.raise_for_status()
                return resp.json().get("total", 0)
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error counting users: {e}")
            return 0

    def rotate_user_salt(self, username: str) -> str | None:
        """Rotate a user's login salt via API."""
        try:
            with self._client() as client:
                resp = client.post(f"/api/v1/users/{username}/rotate-salt")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return None
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                return resp.json().get("status", "rotated")
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error rotating salt for {username}: {e}")
            return None

    # -------------------------------------------------------------------
    # User properties
    # -------------------------------------------------------------------

    def get_user_properties(self, username: str, app: str) -> dict[str, str | None]:
        """Get all properties for a user+app via API."""
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/users/{username}/properties/{app}")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return {}
                if resp.status_code == 404:
                    return {}
                resp.raise_for_status()
                return resp.json().get("properties", {})
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error getting properties for {username}: {e}")
            return {}

    def get_user_property(self, username: str, app: str, key: str) -> str | None:
        """Get a single property value via API."""
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/users/{username}/properties/{app}/{key}")
                if resp.status_code in (401, 404):
                    return None
                resp.raise_for_status()
                return resp.json().get("value")
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting property {key} for {username}: {e}")
            return None

    def set_user_properties(
        self, username: str, app: str, properties: dict[str, str | None]
    ) -> dict[str, str | None]:
        """Bulk upsert properties via API."""
        try:
            with self._client() as client:
                resp = client.put(
                    f"/api/v1/users/{username}/properties/{app}",
                    json={"properties": properties},
                )
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return {}
                resp.raise_for_status()
                return resp.json().get("properties", {})
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error setting properties for {username}: {e}")
            return {}

    def set_user_property(self, username: str, app: str, key: str, value: str | None) -> None:
        """Set a single property via API."""
        try:
            with self._client() as client:
                resp = client.put(
                    f"/api/v1/users/{username}/properties/{app}/{key}",
                    json={"value": value},
                )
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                resp.raise_for_status()
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error setting property {key} for {username}: {e}")

    def delete_user_property(self, username: str, app: str, key: str) -> bool:
        """Delete a single property via API."""
        try:
            with self._client() as client:
                resp = client.delete(f"/api/v1/users/{username}/properties/{app}/{key}")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return False
                if resp.status_code == 404:
                    return False
                resp.raise_for_status()
                return True
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting property {key} for {username}: {e}")
            return False

    def delete_user_properties(self, username: str, app: str) -> int:
        """Delete all properties for a user+app via API."""
        try:
            with self._client() as client:
                resp = client.delete(f"/api/v1/users/{username}/properties/{app}")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return 0
                if resp.status_code == 404:
                    return 0
                resp.raise_for_status()
                return resp.json().get("count", 0)
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error deleting properties for {username}: {e}")
            return 0

    # -------------------------------------------------------------------
    # Group management
    # -------------------------------------------------------------------

    def create_group(self, name: str, description: str = "") -> Group | None:
        """Create a new group via API."""
        try:
            with self._client() as client:
                resp = client.post(
                    "/api/v1/groups",
                    json={"name": name, "description": description},
                )
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return None
                if resp.status_code == 409:
                    logger.error(f"Group {name} already exists")
                    return None
                if resp.status_code != 201:
                    logger.error(f"Failed to create group {name}: {resp.status_code} - {resp.text}")
                    return None
                data = resp.json()
                return Group(
                    name=data["name"],
                    description=data.get("description", ""),
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating group {name}: {e}")
            return None

    def update_group(self, name: str, description: str) -> Group | None:
        """Update a group via API."""
        try:
            with self._client() as client:
                resp = client.patch(
                    f"/api/v1/groups/{name}",
                    json={"description": description},
                )
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return None
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
                return Group(
                    name=data["name"],
                    description=data.get("description", ""),
                )
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error updating group {name}: {e}")
            return None

    def delete_group(self, name: str) -> bool:
        """Delete a group via API."""
        try:
            with self._client() as client:
                resp = client.delete(f"/api/v1/groups/{name}")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return False
                if resp.status_code == 404:
                    return False
                if resp.status_code == 400:
                    logger.error(f"Cannot delete group {name}: {resp.text}")
                    return False
                resp.raise_for_status()
                return True
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting group {name}: {e}")
            return False

    def list_groups(self) -> list[Group]:
        """List all groups via API."""
        try:
            with self._client() as client:
                resp = client.get("/api/v1/groups")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return []
                resp.raise_for_status()
                data = resp.json()
                return [
                    Group(
                        name=g["name"],
                        description=g.get("description", ""),
                    )
                    for g in data.get("groups", [])
                ]
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing groups: {e}")
            return []

    def get_group_members(self, name: str) -> list[str]:
        """List members of a group via API."""
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/groups/{name}/members")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return []
                if resp.status_code == 404:
                    return []
                resp.raise_for_status()
                return resp.json().get("members", [])
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting members of {name}: {e}")
            return []

    def add_group_member(self, group_name: str, username: str) -> bool:
        """Add a member to a group via API."""
        try:
            with self._client() as client:
                resp = client.post(
                    f"/api/v1/groups/{group_name}/members",
                    json={"username": username},
                )
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return False
                if resp.status_code in (404, 409):
                    return False
                if resp.status_code != 201:
                    logger.error(
                        f"Failed to add {username} to {group_name}: "
                        f"{resp.status_code} - {resp.text}"
                    )
                    return False
                return True
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error adding {username} to {group_name}: {e}")
            return False

    def remove_group_member(self, group_name: str, username: str) -> bool:
        """Remove a member from a group via API."""
        try:
            with self._client() as client:
                resp = client.delete(f"/api/v1/groups/{group_name}/members/{username}")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return False
                if resp.status_code == 404:
                    return False
                resp.raise_for_status()
                return True
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error removing {username} from {group_name}: {e}")
            return False

    # -------------------------------------------------------------------
    # System
    # -------------------------------------------------------------------

    def rotate_app_salt(self) -> str:
        """Rotate the global app salt via API."""
        try:
            with self._client() as client:
                resp = client.post("/api/v1/system/rotate-app-salt")
                if resp.status_code == 401:
                    logger.error("Gatekeeper API auth failed (invalid API key?)")
                    return ""
                resp.raise_for_status()
                return resp.json().get("app_salt", "")
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return ""
        except Exception as e:
            logger.error(f"Unexpected error rotating app salt: {e}")
            return ""
