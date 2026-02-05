"""App settings model (key-value store)."""

from gatekeeper.db import get_db, transaction


class AppSetting:
    @staticmethod
    def get(key: str) -> str | None:
        """Get a setting value by key."""
        db = get_db()
        row = db.execute("SELECT value FROM app_setting WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else None

    @staticmethod
    def set(key: str, value: str, description: str | None = None) -> None:
        """Set a setting value, creating or updating as needed."""
        with transaction() as cursor:
            if description is not None:
                cursor.execute(
                    "INSERT INTO app_setting (key, value, description) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                    "description = excluded.description",
                    (key, value, description),
                )
            else:
                cursor.execute(
                    "INSERT INTO app_setting (key, value, description) VALUES (?, ?, '') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )

    @staticmethod
    def get_app_salt() -> str:
        """Get the global app salt. Creates one if missing."""
        import secrets

        salt = AppSetting.get("app_salt")
        if salt is None:
            salt = secrets.token_hex(16)
            AppSetting.set("app_salt", salt, "Global session invalidation salt")
        return salt

    @staticmethod
    def rotate_app_salt() -> str:
        """Rotate the global app salt, invalidating all sessions."""
        import secrets

        new_salt = secrets.token_hex(16)
        AppSetting.set("app_salt", new_salt)
        return new_salt

    @staticmethod
    def get_all() -> list[tuple[str, str, str | None]]:
        """Get all settings as (key, value, description) tuples."""
        db = get_db()
        rows = db.execute("SELECT key, value, description FROM app_setting ORDER BY key").fetchall()
        return [(str(row[0]), str(row[1]), str(row[2]) if row[2] else None) for row in rows]

    @staticmethod
    def get_secret_key() -> str:
        """Get the SECRET_KEY used for token signing."""
        return AppSetting.get("secret_key") or ""

    @staticmethod
    def rotate_secret_key() -> str:
        """Generate and store a new SECRET_KEY. Invalidates all tokens."""
        import secrets

        new_key = secrets.token_urlsafe(32)
        AppSetting.set("secret_key", new_key, "Secret key for signing auth tokens")
        return new_key
