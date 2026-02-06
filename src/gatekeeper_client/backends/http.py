"""HTTP API backend for GatekeeperClient (remote auth server)."""

import logging

import httpx

from gatekeeper_client.models import Group, User

logger = logging.getLogger("gatekeeper_client.http")


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

    def get_user(self, username: str) -> User | None:
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/users/{username}")
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401:
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
                    return None
                resp.raise_for_status()
                data = resp.json()
                groups_resp = client.get(f"/api/v1/users/{username}/groups")
                groups = groups_resp.json().get("groups", []) if groups_resp.status_code == 200 else []
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
            logger.error(f"Gatekeeper API error getting user {username}: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting user {username} from Gatekeeper: {e}")
            return None

    def get_user_groups(self, username: str) -> list[str]:
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/users/{username}/groups")
                if resp.status_code == 401:
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
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
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
                    return ""
                resp.raise_for_status()
                return resp.json()["app_salt"]
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Gatekeeper at {self.server_url}: {e}")
            return ""
        except httpx.HTTPStatusError as e:
            logger.error(f"Gatekeeper API error getting app_salt: {e.response.status_code} - {e.response.text}")
            return ""
        except Exception as e:
            logger.error(f"Unexpected error getting app_salt from Gatekeeper: {e}")
            return ""

    def get_group(self, name: str) -> Group | None:
        try:
            with self._client() as client:
                resp = client.get(f"/api/v1/groups/{name}")
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401:
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
                    return None
                resp.raise_for_status()
                data = resp.json()
                members_resp = client.get(f"/api/v1/groups/{name}/members")
                members = (
                    members_resp.json().get("members", []) if members_resp.status_code == 200 else []
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
            logger.error(f"Gatekeeper API error getting group {name}: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting group {name}: {e}")
            return None

    def resolve_identifier(self, identifier: str) -> User | None:
        try:
            with self._client() as client:
                resp = client.post(
                    "/api/v1/auth/resolve",
                    json={"identifier": identifier},
                )
                if resp.status_code == 401:
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
                    return None
                if resp.status_code == 404:
                    logger.debug(f"User not found for identifier: {identifier}")
                    return None
                if resp.status_code != 200:
                    logger.warning(f"Failed to resolve identifier {identifier}: {resp.status_code} - {resp.text}")
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
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
                    return False
                if resp.status_code != 200:
                    logger.error(f"Failed to send magic link for {user.username}: {resp.status_code} - {resp.text}")
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
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
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
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
                    return None
                if resp.status_code != 200:
                    logger.error(f"Failed to create token for {username}: {resp.status_code} - {resp.text}")
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
                    logger.error(f"Gatekeeper API auth failed (invalid API key?): {resp.status_code}")
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
