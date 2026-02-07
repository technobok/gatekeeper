"""User property model — per-user, per-app key/value metadata."""

from dataclasses import dataclass

from gatekeeper.db import get_db, transaction


@dataclass
class UserProperty:
    username: str
    app: str
    key: str
    value: str | None

    @staticmethod
    def _from_row(row: tuple) -> "UserProperty":
        return UserProperty(
            username=row[0],
            app=row[1],
            key=row[2],
            value=row[3],
        )

    @staticmethod
    def get(username: str, app: str, key: str) -> "UserProperty | None":
        """Get a single property."""
        db = get_db()
        row = db.execute(
            "SELECT username, app, key, value FROM user_property "
            "WHERE LOWER(username) = ? AND app = ? AND key = ?",
            (username.lower(), app, key),
        ).fetchone()
        return UserProperty._from_row(row) if row else None

    @staticmethod
    def get_all(username: str, app: str) -> dict[str, str | None]:
        """Get all properties for a user+app as a dict."""
        db = get_db()
        rows = db.execute(
            "SELECT key, value FROM user_property "
            "WHERE LOWER(username) = ? AND app = ? ORDER BY key",
            (username.lower(), app),
        ).fetchall()
        return {str(r[0]): r[1] for r in rows}

    @staticmethod
    def set(username: str, app: str, key: str, value: str | None) -> None:
        """Upsert a single property."""
        with transaction() as cursor:
            cursor.execute(
                "INSERT INTO user_property (username, app, key, value) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(username, app, key) DO UPDATE SET value = excluded.value",
                (username.lower(), app, key, value),
            )

    @staticmethod
    def set_many(username: str, app: str, properties: dict[str, str | None]) -> None:
        """Bulk upsert properties."""
        username = username.lower()
        with transaction() as cursor:
            for key, value in properties.items():
                cursor.execute(
                    "INSERT INTO user_property (username, app, key, value) "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(username, app, key) DO UPDATE SET value = excluded.value",
                    (username, app, key, value),
                )

    @staticmethod
    def delete(username: str, app: str, key: str) -> bool:
        """Delete a single property. Returns True if a row was deleted."""
        with transaction() as cursor:
            cursor.execute(
                "DELETE FROM user_property "
                "WHERE LOWER(username) = ? AND app = ? AND key = ?",
                (username.lower(), app, key),
            )
            row = cursor.execute("SELECT changes()").fetchone()
            return bool(row and row[0] > 0)

    @staticmethod
    def delete_app(username: str, app: str) -> int:
        """Delete all properties for a user+app. Returns count of rows deleted."""
        with transaction() as cursor:
            cursor.execute(
                "DELETE FROM user_property WHERE LOWER(username) = ? AND app = ?",
                (username.lower(), app),
            )
            row = cursor.execute("SELECT changes()").fetchone()
            return int(row[0]) if row else 0
