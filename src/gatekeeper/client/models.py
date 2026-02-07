"""Standalone dataclasses for the client library (no Flask dependency)."""

from dataclasses import dataclass


@dataclass
class User:
    username: str
    email: str
    fullname: str
    enabled: bool
    groups: list[str] | None = None

    def in_group(self, group_name: str) -> bool:
        """Check if user is in a specific group."""
        if self.groups is None:
            return False
        return group_name in self.groups


@dataclass
class Group:
    name: str
    description: str
    members: list[str] | None = None
