"""HTTP API backend for GatekeeperClient (remote auth server)."""

import httpx

from gatekeeper_client.models import Group, User


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
        with self._client() as client:
            resp = client.get(f"/api/v1/users/{username}")
            if resp.status_code == 404:
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

    def get_user_groups(self, username: str) -> list[str]:
        with self._client() as client:
            resp = client.get(f"/api/v1/users/{username}/groups")
            if resp.status_code != 200:
                return []
            return resp.json().get("groups", [])

    def get_app_salt(self) -> str:
        with self._client() as client:
            resp = client.get("/api/v1/system/app-salt")
            resp.raise_for_status()
            return resp.json()["app_salt"]

    def get_group(self, name: str) -> Group | None:
        with self._client() as client:
            resp = client.get(f"/api/v1/groups/{name}")
            if resp.status_code == 404:
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

    def resolve_identifier(self, identifier: str) -> User | None:
        with self._client() as client:
            resp = client.post(
                "/api/v1/auth/resolve",
                json={"identifier": identifier},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            return User(
                username=data["username"],
                email=data["email"],
                fullname=data.get("fullname", ""),
                enabled=data.get("enabled", True),
            )

    def send_magic_link_email(self, user: User, callback_url: str, redirect_url: str) -> bool:
        with self._client() as client:
            resp = client.post(
                "/api/v1/auth/send-magic-link",
                json={
                    "identifier": user.username,
                    "callback_url": callback_url,
                    "redirect_url": redirect_url,
                },
            )
            return resp.status_code == 200

    def verify_token(self, token: str) -> User | None:
        """Ask the server to verify a token (alternative to local verification)."""
        with self._client() as client:
            resp = client.post(
                "/api/v1/auth/verify-token",
                json={"token": token},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            return User(
                username=data["username"],
                email=data["email"],
                fullname=data.get("fullname", ""),
                enabled=data.get("enabled", True),
                groups=data.get("groups"),
            )

    def create_token(self, username: str, lifetime_seconds: int = 86400) -> str | None:
        """Ask the server to create an auth token."""
        with self._client() as client:
            resp = client.post(
                "/api/v1/auth/create-token",
                json={"username": username, "lifetime_seconds": lifetime_seconds},
            )
            if resp.status_code != 200:
                return None
            return resp.json()["token"]
