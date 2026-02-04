"""API key model."""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from gatekeeper.db import get_db, transaction

_API_KEY_COLUMNS = "id, key, description, enabled, created_at, last_used_at"


@dataclass
class ApiKey:
    id: int
    key: str
    description: str
    enabled: bool
    created_at: str
    last_used_at: str | None

    @staticmethod
    def _from_row(row: tuple) -> ApiKey:
        return ApiKey(
            id=row[0],
            key=row[1],
            description=row[2],
            enabled=bool(row[3]),
            created_at=row[4],
            last_used_at=row[5],
        )

    @staticmethod
    def generate(description: str = "") -> ApiKey:
        """Generate a new API key."""
        raw_key = "gk_" + secrets.token_urlsafe(32)
        now = datetime.now(UTC).isoformat()

        with transaction() as cursor:
            cursor.execute(
                "INSERT INTO api_key (key, description, enabled, created_at) VALUES (?, ?, 1, ?)",
                (raw_key, description, now),
            )
            row = cursor.execute("SELECT last_insert_rowid()").fetchone()
            key_id = int(row[0]) if row else 0

        return ApiKey(
            id=key_id,
            key=raw_key,
            description=description,
            enabled=True,
            created_at=now,
            last_used_at=None,
        )

    @staticmethod
    def verify(raw_key: str) -> ApiKey | None:
        """Verify an API key and return the ApiKey if valid and enabled."""
        db = get_db()
        row = db.execute(
            f"SELECT {_API_KEY_COLUMNS} FROM api_key WHERE key = ? AND enabled = 1",
            (raw_key,),
        ).fetchone()

        if row is None:
            return None

        api_key = ApiKey._from_row(row)
        now = datetime.now(UTC).isoformat()
        with transaction() as cursor:
            cursor.execute(
                "UPDATE api_key SET last_used_at = ? WHERE id = ?",
                (now, api_key.id),
            )
        api_key.last_used_at = now
        return api_key

    @staticmethod
    def get(key_id: int) -> ApiKey | None:
        """Get an API key by ID."""
        db = get_db()
        row = db.execute(
            f"SELECT {_API_KEY_COLUMNS} FROM api_key WHERE id = ?", (key_id,)
        ).fetchone()
        return ApiKey._from_row(row) if row else None

    def disable(self) -> None:
        """Disable this API key."""
        with transaction() as cursor:
            cursor.execute("UPDATE api_key SET enabled = 0 WHERE id = ?", (self.id,))
        self.enabled = False

    def enable(self) -> None:
        """Enable this API key."""
        with transaction() as cursor:
            cursor.execute("UPDATE api_key SET enabled = 1 WHERE id = ?", (self.id,))
        self.enabled = True

    def delete(self) -> None:
        """Delete this API key."""
        with transaction() as cursor:
            cursor.execute("DELETE FROM api_key WHERE id = ?", (self.id,))

    @staticmethod
    def get_all() -> list[ApiKey]:
        """Get all API keys."""
        db = get_db()
        rows = db.execute(
            f"SELECT {_API_KEY_COLUMNS} FROM api_key ORDER BY created_at DESC"
        ).fetchall()
        return [ApiKey._from_row(row) for row in rows]
