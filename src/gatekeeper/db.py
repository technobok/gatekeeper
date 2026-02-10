"""Database connection and transaction handling using APSW."""

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import apsw

_standalone_db: apsw.Connection | None = None


def get_db_path() -> str:
    """Resolve the database path.

    Priority:
      1. GATEKEEPER_DB environment variable
      2. Flask current_app.config["DATABASE_PATH"] (if in app context)
      3. instance/gatekeeper.sqlite3 relative to project root (fallback)
    """
    import os

    db_path = os.environ.get("GATEKEEPER_DB")
    if db_path:
        return db_path

    try:
        from flask import current_app

        return current_app.config["DATABASE_PATH"]
    except (RuntimeError, KeyError):
        pass

    source_root = Path(__file__).parent.parent.parent
    return str(source_root / "instance" / "gatekeeper.sqlite3")


def _configure_connection(conn: apsw.Connection) -> None:
    """Apply standard PRAGMAs to a connection."""
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")


def get_db() -> apsw.Connection:
    """Get the database connection for the current request (Flask context)."""
    from flask import g

    if "db" not in g:
        db_path = get_db_path()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        g.db = apsw.Connection(db_path)
        _configure_connection(g.db)
    return g.db


def close_db(e: BaseException | None = None) -> None:
    """Close the database connection at the end of the request."""
    from flask import g

    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Standalone DB access (no Flask context required)
# ---------------------------------------------------------------------------


def get_standalone_db() -> apsw.Connection:
    """Get a database connection without Flask context.

    Used by CLI commands that don't need the full Flask app.
    The connection is cached at module level.
    """
    global _standalone_db
    if _standalone_db is None:
        db_path = get_db_path()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        _standalone_db = apsw.Connection(db_path)
        _configure_connection(_standalone_db)
    return _standalone_db


def close_standalone_db() -> None:
    """Close the standalone database connection."""
    global _standalone_db
    if _standalone_db is not None:
        _standalone_db.close()
        _standalone_db = None


@contextmanager
def standalone_transaction() -> Generator[apsw.Cursor]:
    """Transaction context manager for standalone (non-Flask) DB access."""
    db = get_standalone_db()
    cursor = db.cursor()
    cursor.execute("BEGIN IMMEDIATE;")
    try:
        yield cursor
        cursor.execute("COMMIT;")
    except Exception:
        cursor.execute("ROLLBACK;")
        raise


# ---------------------------------------------------------------------------
# Flask-context transactions
# ---------------------------------------------------------------------------


@contextmanager
def transaction() -> Generator[apsw.Cursor]:
    """Context manager for database transactions.

    Automatically commits on success, rolls back on exception.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("BEGIN IMMEDIATE;")
    try:
        yield cursor
        cursor.execute("COMMIT;")
    except Exception:
        cursor.execute("ROLLBACK;")
        raise


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


def init_db_at(db_path: str) -> None:
    """Initialize the database schema at the given path.

    Works without Flask context.
    """
    import secrets

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = apsw.Connection(db_path)
    _configure_connection(conn)

    schema_path = Path(__file__).parent.parent.parent / "database" / "schema.sql"
    with open(schema_path) as f:
        for _ in conn.execute(f.read()):
            pass

    # Generate secret_key if not exists
    row = conn.execute("SELECT value FROM app_setting WHERE key = 'secret_key'").fetchone()
    if not row:
        new_key = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT OR IGNORE INTO app_setting (key, value, description) VALUES (?, ?, ?)",
            ("secret_key", new_key, "Secret key for signing auth tokens"),
        )

    conn.close()


def init_db() -> None:
    """Initialize the database with the schema (Flask context)."""
    db_path = get_db_path()
    init_db_at(db_path)


def get_schema_version() -> int:
    """Get the current schema version from db_metadata."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT value FROM db_metadata WHERE key = 'schema_version'")
        row = cursor.fetchone()
        return int(row[0]) if row else 0
    except apsw.SQLError:
        return 0


CURRENT_SCHEMA_VERSION = 2


def migrate_db() -> None:
    """Run any pending schema migrations (Flask context required)."""
    version = get_schema_version()
    if version >= CURRENT_SCHEMA_VERSION:
        return

    if version < 2:
        _migrate_v1_to_v2()


def _migrate_v1_to_v2() -> None:
    """Add user_property table and bump schema version to 2."""
    with transaction() as cursor:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS user_property ("
            "    username TEXT NOT NULL REFERENCES user(username) ON DELETE CASCADE,"
            "    app      TEXT NOT NULL,"
            "    key      TEXT NOT NULL,"
            "    value    TEXT,"
            "    PRIMARY KEY (username, app, key)"
            ");"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_property_username ON user_property(username);"
        )
        cursor.execute("UPDATE db_metadata SET value = '2' WHERE key = 'schema_version';")
