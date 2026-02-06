"""Local SQLite backend for GatekeeperClient (direct DB access)."""

from pathlib import Path

import apsw

from gatekeeper_client.models import Group, User


class LocalBackend:
    """Backend that reads directly from the Gatekeeper SQLite database."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def _connect(self) -> apsw.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = apsw.Connection(self.db_path, flags=apsw.SQLITE_OPEN_READONLY)
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def get_user(self, username: str) -> User | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT username, email, fullname, enabled FROM user WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return None
            groups = self.get_user_groups(username)
            return User(
                username=str(row[0]),
                email=str(row[1]),
                fullname=str(row[2]),
                enabled=bool(row[3]),
                groups=groups,
            )
        finally:
            conn.close()

    def get_user_login_salt(self, username: str) -> str | None:
        """Get a user's login_salt (needed for token verification)."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT login_salt FROM user WHERE username = ?", (username,)
            ).fetchone()
            return str(row[0]) if row else None
        finally:
            conn.close()

    def get_user_groups(self, username: str) -> list[str]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT group_name FROM group_user WHERE username = ? ORDER BY group_name",
                (username,),
            ).fetchall()
            return [str(row[0]) for row in rows]
        finally:
            conn.close()

    def get_app_salt(self) -> str:
        conn = self._connect()
        try:
            row = conn.execute("SELECT value FROM app_setting WHERE key = 'app_salt'").fetchone()
            return str(row[0]) if row else ""
        finally:
            conn.close()

    def get_secret_key(self) -> str:
        """Get SECRET_KEY from database."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM app_setting WHERE key = 'secret_key'"
            ).fetchone()
            return str(row[0]) if row else ""
        finally:
            conn.close()

    def get_group(self, name: str) -> Group | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT name, description FROM grp WHERE name = ?", (name,)
            ).fetchone()
            if row is None:
                return None
            members_rows = conn.execute(
                "SELECT username FROM group_user WHERE group_name = ? ORDER BY username",
                (name,),
            ).fetchall()
            return Group(
                name=str(row[0]),
                description=str(row[1]),
                members=[str(r[0]) for r in members_rows],
            )
        finally:
            conn.close()

    def resolve_identifier(self, identifier: str) -> User | None:
        """Resolve login identifier to a user (local DB only, no LDAP)."""
        if "@" in identifier:
            # Email lookup
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT username, email, fullname, enabled FROM user "
                    "WHERE email = ? AND enabled = 1",
                    (identifier,),
                ).fetchall()
                if len(rows) == 1:
                    row = rows[0]
                    return User(
                        username=str(row[0]),
                        email=str(row[1]),
                        fullname=str(row[2]),
                        enabled=bool(row[3]),
                    )
                return None
            finally:
                conn.close()
        else:
            # Direct username lookup (domain\user or bare)
            return self.get_user(identifier)

    def send_magic_link_email(
        self, user: User, callback_url: str, redirect_url: str, app_name: str | None = None
    ) -> bool:
        # Local backend cannot send emails directly - that's the server's job.
        # The consuming app should handle this via its own email service.
        return False
