"""Abstract backend protocol for GatekeeperClient."""

from typing import Protocol

from gatekeeper_client.models import Group, User


class GatekeeperBackend(Protocol):
    """Protocol that all backends must implement."""

    def get_user(self, username: str) -> User | None:
        """Look up a user by username."""
        ...

    def get_user_groups(self, username: str) -> list[str]:
        """Get group names for a user."""
        ...

    def get_app_salt(self) -> str:
        """Get the current global app salt."""
        ...

    def get_group(self, name: str) -> Group | None:
        """Look up a group by name."""
        ...

    def resolve_identifier(self, identifier: str) -> User | None:
        """Resolve a login identifier (email, domain\\user, or bare username) to a user."""
        ...

    def send_magic_link_email(self, user: User, callback_url: str, redirect_url: str) -> bool:
        """Send a magic link email to the user. Returns True if sent."""
        ...

    def get_user_properties(self, username: str, app: str) -> dict[str, str | None]:
        """Get all properties for a user+app."""
        ...

    def get_user_property(self, username: str, app: str, key: str) -> str | None:
        """Get a single property value."""
        ...

    def set_user_properties(self, username: str, app: str, properties: dict[str, str | None]) -> dict[str, str | None]:
        """Bulk upsert properties. Returns the properties dict."""
        ...

    def set_user_property(self, username: str, app: str, key: str, value: str | None) -> None:
        """Set a single property."""
        ...

    def delete_user_property(self, username: str, app: str, key: str) -> bool:
        """Delete a single property. Returns True if deleted."""
        ...

    def delete_user_properties(self, username: str, app: str) -> int:
        """Delete all properties for a user+app. Returns count deleted."""
        ...
