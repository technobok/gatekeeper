"""API key model."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from gatekeeper.db import get_db, transaction

_API_KEY_COLUMNS = "id, key_prefix, key_hash, description, enabled, created_at, last_used_at"


@dataclass
class ApiKey:
    id: int
    key_prefix: str
    key_hash: str
    description: str
    enabled: bool
    created_at: str
    last_used_at: str | None

    @staticmethod
    def _from_row(row: tuple) -> ApiKey:
        return ApiKey(
            id=row[0],
            key_prefix=row[1],
            key_hash=row[2],
            description=row[3],
            enabled=bool(row[4]),
            created_at=row[5],
            last_used_at=row[6],
        )

    @staticmethod
    def generate(description: str = "") -> tuple[ApiKey, str]:
        """Generate a new API key. Returns (ApiKey, raw_key).

        The raw key is only available at creation time.
        """
        raw_key = "gk_" + secrets.token_urlsafe(32)
        key_prefix = raw_key[:11]  # "gk_" + 8 chars
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        now = datetime.now(UTC).isoformat()

        with transaction() as cursor:
            cursor.execute(
                "INSERT INTO api_key (key_prefix, key_hash, description, enabled, created_at) "
                "VALUES (?, ?, ?, 1, ?)",
                (key_prefix, key_hash, description, now),
            )
            row = cursor.execute("SELECT last_insert_rowid()").fetchone()
            key_id = int(row[0]) if row else 0

        api_key = ApiKey(
            id=key_id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            description=description,
            enabled=True,
            created_at=now,
            last_used_at=None,
        )
        return api_key, raw_key

    @staticmethod
    def verify(raw_key: str) -> ApiKey | None:
        """Verify an API key and return the ApiKey if valid and enabled."""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db = get_db()
        row = db.execute(
            f"SELECT {_API_KEY_COLUMNS} FROM api_key WHERE key_hash = ? AND enabled = 1",
            (key_hash,),
        ).fetchone()

        if row is None:
            return None

        api_key = ApiKey._from_row(row)
        # Update last_used_at
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
