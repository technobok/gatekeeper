"""Standalone dataclasses for the client library (no Flask dependency)."""

from dataclasses import dataclass, fields


@dataclass
class User:
    username: str
    email: str
    fullname: str
    enabled: bool
    groups: list[str] | None = None
    # Directory profile, filled by get_user (empty from an older Gatekeeper, and on list results).
    given_name: str = ""
    display_name: str = ""
    title: str = ""
    department: str = ""
    office: str = ""
    city: str = ""
    state: str = ""
    country_code: str = ""
    country: str = ""
    company: str = ""
    employee_type: str = ""

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


# The User fields get_user fills from the directory profile, in declaration order.
PROFILE_FIELDS = tuple(
    f.name
    for f in fields(User)
    if f.name not in ("username", "email", "fullname", "enabled", "groups")
)
