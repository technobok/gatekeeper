"""Group model."""

from dataclasses import dataclass
from datetime import UTC, datetime

from gatekeeper.db import get_db, transaction

_GROUP_COLUMNS = "name, description, created_at, updated_at, source"


@dataclass
class Group:
    name: str
    description: str
    created_at: str
    updated_at: str
    source: str = "gatekeeper"

    @staticmethod
    def _from_row(row: tuple) -> Group:
        return Group(
            name=row[0],
            description=row[1],
            created_at=row[2],
            updated_at=row[3],
            source=row[4],
        )

    @staticmethod
    def get(name: str) -> Group | None:
        """Get group by name (primary key)."""
        db = get_db()
        row = db.execute(f"SELECT {_GROUP_COLUMNS} FROM grp WHERE name = ?", (name,)).fetchone()
        return Group._from_row(row) if row else None

    @staticmethod
    def create(name: str, description: str = "", source: str = "gatekeeper") -> Group:
        """Create a new group."""
        now = datetime.now(UTC).isoformat()

        with transaction() as cursor:
            cursor.execute(
                "INSERT INTO grp (name, description, created_at, updated_at, source) VALUES (?, ?, ?, ?, ?)",
                (name, description, now, now, source),
            )

        return Group(
            name=name, description=description, created_at=now, updated_at=now, source=source
        )

    def update(self, description: str | None = None) -> None:
        """Update group fields."""
        if description is None:
            return

        now = datetime.now(UTC).isoformat()
        with transaction() as cursor:
            cursor.execute(
                "UPDATE grp SET description = ?, updated_at = ? WHERE name = ?",
                (description, now, self.name),
            )
        self.description = description
        self.updated_at = now

    def delete(self) -> None:
        """Delete this group."""
        with transaction() as cursor:
            cursor.execute("DELETE FROM grp WHERE name = ?", (self.name,))

    @staticmethod
    def get_all() -> list[Group]:
        """Get all groups."""
        db = get_db()
        rows = db.execute(f"SELECT {_GROUP_COLUMNS} FROM grp ORDER BY name").fetchall()
        return [Group._from_row(row) for row in rows]

    @staticmethod
    def count() -> int:
        """Count groups."""
        db = get_db()
        row = db.execute("SELECT COUNT(*) FROM grp").fetchone()
        return int(row[0]) if row else 0

    def get_members(self) -> list[str]:
        """Get usernames of all members in this group."""
        db = get_db()
        rows = db.execute(
            "SELECT username FROM group_user WHERE group_name = ? ORDER BY username",
            (self.name,),
        ).fetchall()
        return [str(row[0]) for row in rows]

    def add_member(self, username: str) -> bool:
        """Add a user to this group. Returns False if already a member."""
        now = datetime.now(UTC).isoformat()
        try:
            with transaction() as cursor:
                cursor.execute(
                    "INSERT INTO group_user (group_name, username, created_at) VALUES (?, ?, ?)",
                    (self.name, username, now),
                )
            return True
        except Exception:
            return False

    def remove_member(self, username: str) -> bool:
        """Remove a user from this group. Returns True if removed."""
        with transaction() as cursor:
            cursor.execute(
                "DELETE FROM group_user WHERE group_name = ? AND LOWER(username) = ?",
                (self.name, username.lower()),
            )
            # Check if a row was actually deleted
            row = cursor.execute("SELECT changes()").fetchone()
            return bool(row and row[0] > 0)

    @staticmethod
    def get_groups_for_user(username: str) -> list[str]:
        """Get group names for a user. Case-insensitive lookup."""
        db = get_db()
        rows = db.execute(
            "SELECT group_name FROM group_user WHERE LOWER(username) = ? ORDER BY group_name",
            (username.lower(),),
        ).fetchall()
        return [str(row[0]) for row in rows]

    @staticmethod
    def get_groups_for_user_with_source(username: str) -> list[tuple[str, str]]:
        """Get (group_name, source) pairs for a user. Case-insensitive lookup."""
        db = get_db()
        rows = db.execute(
            "SELECT gu.group_name, g.source FROM group_user gu "
            "JOIN grp g ON gu.group_name = g.name "
            "WHERE LOWER(gu.username) = ? ORDER BY gu.group_name",
            (username.lower(),),
        ).fetchall()
        return [(str(row[0]), str(row[1])) for row in rows]

    @staticmethod
    def user_in_group(username: str, group_name: str) -> bool:
        """Check if a user is in a specific group. Case-insensitive username lookup."""
        db = get_db()
        row = db.execute(
            "SELECT 1 FROM group_user WHERE group_name = ? AND LOWER(username) = ?",
            (group_name, username.lower()),
        ).fetchone()
        return row is not None
