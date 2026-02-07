"""User model."""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from gatekeeper.db import get_db, transaction

_USER_COLUMNS = "username, email, fullname, enabled, login_salt, created_at, updated_at"


@dataclass
class User:
    username: str
    email: str
    fullname: str
    enabled: bool
    login_salt: str
    created_at: str
    updated_at: str

    @staticmethod
    def _from_row(row: tuple) -> User:
        return User(
            username=row[0],
            email=row[1],
            fullname=row[2],
            enabled=bool(row[3]),
            login_salt=row[4],
            created_at=row[5],
            updated_at=row[6],
        )

    @staticmethod
    def get(username: str) -> User | None:
        """Get user by username (primary key). Case-insensitive lookup."""
        db = get_db()
        row = db.execute(
            f"SELECT {_USER_COLUMNS} FROM user WHERE LOWER(username) = ?", (username.lower(),)
        ).fetchone()
        return User._from_row(row) if row else None

    @staticmethod
    def get_by_email(email: str) -> list[User]:
        """Get all users matching an email address."""
        db = get_db()
        rows = db.execute(
            f"SELECT {_USER_COLUMNS} FROM user WHERE email = ? AND enabled = 1",
            (email,),
        ).fetchall()
        return [User._from_row(row) for row in rows]

    @staticmethod
    def create(
        username: str,
        email: str,
        fullname: str = "",
        enabled: bool = True,
    ) -> User:
        """Create a new user. Username is stored lowercase."""
        username = username.lower()
        now = datetime.now(UTC).isoformat()
        login_salt = secrets.token_hex(8)

        with transaction() as cursor:
            cursor.execute(
                "INSERT INTO user (username, email, fullname, enabled, login_salt, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, email, fullname, int(enabled), login_salt, now, now),
            )

        return User(
            username=username,
            email=email,
            fullname=fullname,
            enabled=enabled,
            login_salt=login_salt,
            created_at=now,
            updated_at=now,
        )

    def update(
        self,
        email: str | None = None,
        fullname: str | None = None,
        enabled: bool | None = None,
    ) -> None:
        """Update user fields."""
        now = datetime.now(UTC).isoformat()
        updates: list[str] = []
        params: list[str | int] = []

        if email is not None:
            updates.append("email = ?")
            params.append(email)
            self.email = email

        if fullname is not None:
            updates.append("fullname = ?")
            params.append(fullname)
            self.fullname = fullname

        if enabled is not None:
            updates.append("enabled = ?")
            params.append(int(enabled))
            self.enabled = enabled

        if updates:
            updates.append("updated_at = ?")
            params.append(now)
            params.append(self.username)

            with transaction() as cursor:
                cursor.execute(
                    f"UPDATE user SET {', '.join(updates)} WHERE username = ?",
                    params,
                )
            self.updated_at = now

    def rename(self, new_username: str) -> None:
        """Rename this user (change primary key). Updates all FK references."""
        new_username = new_username.lower()
        now = datetime.now(UTC).isoformat()

        with transaction() as cursor:
            cursor.execute("PRAGMA defer_foreign_keys = ON;")
            cursor.execute(
                "UPDATE group_user SET username = ? WHERE username = ?",
                (new_username, self.username),
            )
            cursor.execute(
                "UPDATE user_property SET username = ? WHERE username = ?",
                (new_username, self.username),
            )
            cursor.execute(
                "UPDATE user SET username = ?, updated_at = ? WHERE username = ?",
                (new_username, now, self.username),
            )
            cursor.execute(
                "UPDATE audit_log SET actor = ? WHERE actor = ?",
                (new_username, self.username),
            )
            cursor.execute(
                "UPDATE audit_log SET target = ? WHERE target = ?",
                (new_username, self.username),
            )

        self.username = new_username
        self.updated_at = now

    def rotate_login_salt(self) -> str:
        """Rotate this user's login salt, invalidating all their sessions."""
        new_salt = secrets.token_hex(8)
        now = datetime.now(UTC).isoformat()

        with transaction() as cursor:
            cursor.execute(
                "UPDATE user SET login_salt = ?, updated_at = ? WHERE username = ?",
                (new_salt, now, self.username),
            )

        self.login_salt = new_salt
        self.updated_at = now
        return new_salt

    @staticmethod
    def get_all(
        enabled_only: bool = False,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[User]:
        """Get all users with optional filtering."""
        conditions: list[str] = []
        params: list[str | int] = []

        if enabled_only:
            conditions.append("enabled = 1")

        if search:
            conditions.append("(username LIKE ? OR email LIKE ? OR fullname LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        db = get_db()
        rows = db.execute(
            f"SELECT {_USER_COLUMNS} FROM user{where} ORDER BY username LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return [User._from_row(row) for row in rows]

    @staticmethod
    def count(enabled_only: bool = False) -> int:
        """Count users."""
        db = get_db()
        if enabled_only:
            row = db.execute("SELECT COUNT(*) FROM user WHERE enabled = 1").fetchone()
        else:
            row = db.execute("SELECT COUNT(*) FROM user").fetchone()
        return int(row[0]) if row else 0

    def delete(self) -> None:
        """Delete this user and all related records."""
        with transaction() as cursor:
            cursor.execute("DELETE FROM user_property WHERE username = ?", (self.username,))
            cursor.execute("DELETE FROM group_user WHERE username = ?", (self.username,))
            cursor.execute("DELETE FROM user WHERE username = ?", (self.username,))
