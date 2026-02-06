"""Local SQLite backend for GatekeeperClient (direct DB access)."""

import json
import logging
import secrets
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import apsw

from gatekeeper_client.models import Group, User
from gatekeeper_client.token import create_magic_link_token

logger = logging.getLogger("gatekeeper_client.local")


class LocalBackend:
    """Backend that reads and writes directly to the Gatekeeper SQLite database."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def _connect(self, readonly: bool = True) -> apsw.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        flags = apsw.SQLITE_OPEN_READONLY if readonly else apsw.SQLITE_OPEN_READWRITE
        conn = apsw.Connection(self.db_path, flags=flags)
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    @contextmanager
    def _transaction(self):
        """Context manager for write transactions. Yields (conn, cursor)."""
        conn = self._connect(readonly=False)
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            yield conn, cursor
            cursor.execute("COMMIT;")
        except Exception:
            cursor.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def _get_setting(self, key: str) -> str | None:
        """Read a single value from app_setting."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM app_setting WHERE key = ?", (key,)
            ).fetchone()
            return str(row[0]) if row else None
        finally:
            conn.close()

    def _audit_log(
        self, action: str, target: str | None = None, details: str | None = None
    ) -> None:
        """Write an entry to the audit log."""
        now = datetime.now(UTC).isoformat()
        conn = self._connect(readonly=False)
        try:
            conn.execute(
                "INSERT INTO audit_log (timestamp, actor, action, target, details) "
                "VALUES (?, ?, ?, ?, ?)",
                (now, "local_client", action, target, details),
            )
        finally:
            conn.close()

    # -----------------------------------------------------------------------
    # Read operations
    # -----------------------------------------------------------------------

    def get_user(self, username: str) -> User | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT username, email, fullname, enabled FROM user "
                "WHERE LOWER(username) = ?",
                (username.lower(),),
            ).fetchone()
            if row is None:
                return None
            groups = self.get_user_groups(str(row[0]))
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
                "SELECT login_salt FROM user WHERE LOWER(username) = ?",
                (username.lower(),),
            ).fetchone()
            return str(row[0]) if row else None
        finally:
            conn.close()

    def get_user_groups(self, username: str) -> list[str]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT group_name FROM group_user "
                "WHERE LOWER(username) = ? ORDER BY group_name",
                (username.lower(),),
            ).fetchall()
            return [str(row[0]) for row in rows]
        finally:
            conn.close()

    def get_app_salt(self) -> str:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM app_setting WHERE key = 'app_salt'"
            ).fetchone()
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

    # -----------------------------------------------------------------------
    # User management
    # -----------------------------------------------------------------------

    def create_user(
        self,
        username: str,
        email: str,
        fullname: str = "",
        enabled: bool = True,
    ) -> User:
        """Create a new user. Username is stored lowercase."""
        username = username.lower()
        now = datetime.now(UTC).isoformat()
        login_salt = secrets.token_hex(8)

        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "INSERT INTO user (username, email, fullname, enabled, login_salt, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, email, fullname, int(enabled), login_salt, now, now),
            )

        self._audit_log("user_created", username, json.dumps({"email": email}))
        return User(
            username=username, email=email, fullname=fullname, enabled=enabled
        )

    def update_user(
        self,
        username: str,
        email: str | None = None,
        fullname: str | None = None,
        enabled: bool | None = None,
    ) -> User | None:
        """Update a user. Returns updated User or None if not found."""
        user = self.get_user(username)
        if user is None:
            return None

        now = datetime.now(UTC).isoformat()
        updates: list[str] = []
        params: list[str | int] = []

        if email is not None:
            updates.append("email = ?")
            params.append(email)
            user.email = email
        if fullname is not None:
            updates.append("fullname = ?")
            params.append(fullname)
            user.fullname = fullname
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(int(enabled))
            user.enabled = enabled

        if updates:
            updates.append("updated_at = ?")
            params.append(now)
            params.append(username.lower())

            with self._transaction() as (_conn, cursor):
                cursor.execute(
                    f"UPDATE user SET {', '.join(updates)} WHERE LOWER(username) = ?",
                    params,
                )

            changes = {
                k: v
                for k, v in {
                    "email": email,
                    "fullname": fullname,
                    "enabled": enabled,
                }.items()
                if v is not None
            }
            self._audit_log("user_updated", username, json.dumps(changes))

        return user

    def delete_user(self, username: str) -> bool:
        """Delete a user and all their group memberships."""
        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "DELETE FROM group_user WHERE LOWER(username) = ?",
                (username.lower(),),
            )
            cursor.execute(
                "DELETE FROM user WHERE LOWER(username) = ?", (username.lower(),)
            )
            row = cursor.execute("SELECT changes()").fetchone()
            deleted = bool(row and row[0] > 0)

        if deleted:
            self._audit_log("user_deleted", username)
        return deleted

    def list_users(
        self,
        search: str | None = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[User]:
        """List users with optional filtering."""
        conditions: list[str] = []
        params: list[str | int] = []

        if enabled_only:
            conditions.append("enabled = 1")
        if search:
            conditions.append(
                "(username LIKE ? OR email LIKE ? OR fullname LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like])

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT username, email, fullname, enabled FROM user{where} "
                "ORDER BY username LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
            return [
                User(
                    username=str(r[0]),
                    email=str(r[1]),
                    fullname=str(r[2]),
                    enabled=bool(r[3]),
                )
                for r in rows
            ]
        finally:
            conn.close()

    def count_users(self, enabled_only: bool = False) -> int:
        """Count users."""
        conn = self._connect()
        try:
            if enabled_only:
                row = conn.execute(
                    "SELECT COUNT(*) FROM user WHERE enabled = 1"
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM user").fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def rotate_user_salt(self, username: str) -> str | None:
        """Rotate a user's login salt, invalidating their sessions."""
        now = datetime.now(UTC).isoformat()
        new_salt = secrets.token_hex(8)

        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "UPDATE user SET login_salt = ?, updated_at = ? "
                "WHERE LOWER(username) = ?",
                (new_salt, now, username.lower()),
            )
            row = cursor.execute("SELECT changes()").fetchone()
            if not row or row[0] == 0:
                return None

        self._audit_log("user_salt_rotated", username)
        return new_salt

    # -----------------------------------------------------------------------
    # Group management
    # -----------------------------------------------------------------------

    def create_group(self, name: str, description: str = "") -> Group:
        """Create a new group."""
        now = datetime.now(UTC).isoformat()

        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "INSERT INTO grp (name, description, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (name, description, now, now),
            )

        self._audit_log("group_created", name)
        return Group(name=name, description=description)

    def update_group(self, name: str, description: str) -> Group | None:
        """Update a group's description. Returns updated Group or None."""
        now = datetime.now(UTC).isoformat()

        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "UPDATE grp SET description = ?, updated_at = ? WHERE name = ?",
                (description, now, name),
            )
            row = cursor.execute("SELECT changes()").fetchone()
            if not row or row[0] == 0:
                return None

        self._audit_log("group_updated", name)
        return Group(name=name, description=description)

    def delete_group(self, name: str) -> bool:
        """Delete a group and all its memberships."""
        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "DELETE FROM group_user WHERE group_name = ?", (name,)
            )
            cursor.execute("DELETE FROM grp WHERE name = ?", (name,))
            row = cursor.execute("SELECT changes()").fetchone()
            deleted = bool(row and row[0] > 0)

        if deleted:
            self._audit_log("group_deleted", name)
        return deleted

    def list_groups(self) -> list[Group]:
        """List all groups."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT name, description FROM grp ORDER BY name"
            ).fetchall()
            return [
                Group(name=str(r[0]), description=str(r[1])) for r in rows
            ]
        finally:
            conn.close()

    def get_group_members(self, name: str) -> list[str]:
        """Get usernames of all members in a group."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT username FROM group_user WHERE group_name = ? "
                "ORDER BY username",
                (name,),
            ).fetchall()
            return [str(r[0]) for r in rows]
        finally:
            conn.close()

    def add_group_member(self, group_name: str, username: str) -> bool:
        """Add a user to a group. Returns False if already a member."""
        now = datetime.now(UTC).isoformat()
        try:
            with self._transaction() as (_conn, cursor):
                cursor.execute(
                    "INSERT INTO group_user (group_name, username, created_at) "
                    "VALUES (?, ?, ?)",
                    (group_name, username.lower(), now),
                )
            self._audit_log("member_added", f"{group_name}/{username}")
            return True
        except apsw.ConstraintError:
            return False

    def remove_group_member(self, group_name: str, username: str) -> bool:
        """Remove a user from a group."""
        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "DELETE FROM group_user "
                "WHERE group_name = ? AND LOWER(username) = ?",
                (group_name, username.lower()),
            )
            row = cursor.execute("SELECT changes()").fetchone()
            removed = bool(row and row[0] > 0)

        if removed:
            self._audit_log("member_removed", f"{group_name}/{username}")
        return removed

    # -----------------------------------------------------------------------
    # System
    # -----------------------------------------------------------------------

    def rotate_app_salt(self) -> str:
        """Rotate the global app salt, invalidating all sessions."""
        new_salt = secrets.token_hex(16)

        with self._transaction() as (_conn, cursor):
            cursor.execute(
                "INSERT INTO app_setting (key, value, description) "
                "VALUES ('app_salt', ?, '') "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (new_salt,),
            )

        self._audit_log(
            "app_salt_rotated", details="All sessions invalidated"
        )
        return new_salt

    # -----------------------------------------------------------------------
    # Identifier resolution with LDAP
    # -----------------------------------------------------------------------

    def _get_ldap_config(self) -> dict[str, str]:
        """Read all LDAP-related settings from the database."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT key, value FROM app_setting WHERE key LIKE 'ldap.%'"
            ).fetchall()
            return {str(r[0]): str(r[1]) for r in rows}
        finally:
            conn.close()

    def _is_ldap_enabled(self) -> bool:
        """Check if LDAP is enabled in configuration."""
        val = self._get_setting("ldap.enabled")
        return val is not None and val.lower() in ("true", "1", "yes", "on")

    def _ldap_lookup_by_username(
        self, config: dict[str, str], domain: str, username: str
    ) -> tuple[str, str, str] | None:
        """Look up a user by username in LDAP.

        Returns (full_username, email, fullname) or None.
        """
        try:
            import ldap
            import ldap.filter
        except ImportError:
            logger.debug("python-ldap not installed, skipping LDAP lookup")
            return None

        server = config.get(f"ldap.{domain}.server", "")
        base_dn = config.get(f"ldap.{domain}.base_dn", "")
        bind_dn = config.get(f"ldap.{domain}.bind_dn", "")
        bind_password = config.get(f"ldap.{domain}.bind_password", "")
        user_filter = config.get(
            f"ldap.{domain}.user_filter",
            "(&(objectClass=user)(sAMAccountName={username}))",
        )
        email_attr = config.get(f"ldap.{domain}.email_attr", "mail")
        fullname_attr = config.get(
            f"ldap.{domain}.fullname_attr", "displayName"
        )
        username_attr = config.get(
            f"ldap.{domain}.username_attr", "sAMAccountName"
        )

        if not server or not base_dn:
            logger.warning(
                f"LDAP config missing for domain {domain}: "
                f"server={server}, base_dn={base_dn}"
            )
            return None

        search_filter = user_filter.replace(
            "{username}", ldap.filter.escape_filter_chars(username)
        )
        logger.debug(f"LDAP search: domain={domain}, filter={search_filter}")

        try:
            conn = ldap.initialize(server)
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)

            if bind_dn:
                conn.simple_bind_s(bind_dn, bind_password)
            else:
                conn.simple_bind_s("", "")

            results = conn.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                [email_attr, fullname_attr, username_attr],
            )
            conn.unbind_s()

            for dn, attrs in results:
                if dn is None:
                    continue
                email = _ldap_get_attr(attrs, email_attr)
                fullname = _ldap_get_attr(attrs, fullname_attr) or ""
                sam = _ldap_get_attr(attrs, username_attr) or username
                if not email:
                    continue
                return f"{domain}\\{sam}", email, fullname

        except Exception as e:
            logger.error(
                f"LDAP lookup failed for {domain}\\{username}: {e}"
            )

        return None

    def _ldap_lookup_by_email(
        self, config: dict[str, str], email: str
    ) -> tuple[str, str, str] | None:
        """Look up a user by email across all LDAP domains.

        Returns (username, email, fullname) or None.
        """
        try:
            import ldap
            import ldap.filter
        except ImportError:
            return None

        domains_raw = config.get("ldap.domains", "")
        domains = [d.strip() for d in domains_raw.split(",") if d.strip()]

        for domain in domains:
            server = config.get(f"ldap.{domain}.server", "")
            base_dn = config.get(f"ldap.{domain}.base_dn", "")
            bind_dn = config.get(f"ldap.{domain}.bind_dn", "")
            bind_password = config.get(f"ldap.{domain}.bind_password", "")
            email_attr = config.get(f"ldap.{domain}.email_attr", "mail")
            email_filter = config.get(f"ldap.{domain}.email_filter", "")
            if not email_filter:
                email_filter = (
                    f"(&(objectClass=user)({email_attr}={{email}}))"
                )
            fullname_attr = config.get(
                f"ldap.{domain}.fullname_attr", "displayName"
            )
            username_attr = config.get(
                f"ldap.{domain}.username_attr", "sAMAccountName"
            )

            if not server or not base_dn:
                continue

            search_filter = email_filter.replace(
                "{email}", ldap.filter.escape_filter_chars(email)
            )

            try:
                conn = ldap.initialize(server)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)

                if bind_dn:
                    conn.simple_bind_s(bind_dn, bind_password)
                else:
                    conn.simple_bind_s("", "")

                results = conn.search_s(
                    base_dn,
                    ldap.SCOPE_SUBTREE,
                    search_filter,
                    [email_attr, fullname_attr, username_attr],
                )
                conn.unbind_s()

                for dn, attrs in results:
                    if dn is None:
                        continue
                    fullname = _ldap_get_attr(attrs, fullname_attr) or ""
                    sam = _ldap_get_attr(attrs, username_attr)
                    if not sam:
                        continue
                    return f"{domain}\\{sam}", email, fullname

            except Exception as e:
                logger.error(
                    f"LDAP email lookup failed in {domain}: {e}"
                )

        return None

    def _auto_provision(
        self, username: str, email: str, fullname: str
    ) -> User:
        """Auto-create a user from LDAP data and add to standard group."""
        existing = self.get_user(username)
        if existing:
            return existing

        user = self.create_user(
            username=username, email=email, fullname=fullname
        )
        self.add_group_member("standard", username)
        self._audit_log(
            "auto_provision", username, f"LDAP auto-provisioned: {email}"
        )
        return user

    def resolve_identifier(self, identifier: str) -> User | None:
        """Resolve login identifier to a user (local DB + optional LDAP).

        Identifier formats:
        1. Email (contains @): look up by email; if >1 match, reject
        2. domain\\username (contains \\): direct DB lookup, then LDAP
        3. Bare username: direct DB lookup, then LDAP across all domains
        """
        ldap_enabled = self._is_ldap_enabled()
        ldap_config = self._get_ldap_config() if ldap_enabled else {}

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
                elif len(rows) > 1:
                    return None  # Multiple matches
            finally:
                conn.close()

            # Try LDAP
            if ldap_enabled:
                result = self._ldap_lookup_by_email(ldap_config, identifier)
                if result:
                    return self._auto_provision(*result)
            return None

        elif "\\" in identifier:
            # domain\username format
            user = self.get_user(identifier)
            if user and user.enabled:
                return user

            # Try LDAP
            if ldap_enabled:
                parts = identifier.split("\\", 1)
                result = self._ldap_lookup_by_username(
                    ldap_config, parts[0], parts[1]
                )
                if result:
                    return self._auto_provision(*result)

            if user and not user.enabled:
                return None  # Disabled
            return None

        else:
            # Bare username
            user = self.get_user(identifier)
            if user and user.enabled:
                return user

            # Try LDAP across all domains
            if ldap_enabled:
                domains_raw = ldap_config.get("ldap.domains", "")
                domains = [
                    d.strip() for d in domains_raw.split(",") if d.strip()
                ]
                for domain in domains:
                    result = self._ldap_lookup_by_username(
                        ldap_config, domain, identifier
                    )
                    if result:
                        return self._auto_provision(*result)

            if user and not user.enabled:
                return None  # Disabled
            return None

    # -----------------------------------------------------------------------
    # Email sending
    # -----------------------------------------------------------------------

    def send_magic_link_email(
        self,
        user: User,
        callback_url: str,
        redirect_url: str,
        app_name: str | None = None,
    ) -> bool:
        """Send a magic link email.

        Tries: outbox DB -> outbox HTTP API.
        """
        secret_key = self.get_secret_key()
        if not secret_key:
            logger.error("Cannot send magic link: no secret_key in database")
            return False

        app_name = app_name or "Gatekeeper"

        # Create the magic link token
        magic_token = create_magic_link_token(
            secret_key, user.username, redirect_url=redirect_url
        )
        if "?" in callback_url:
            full_url = f"{callback_url}&token={magic_token}"
        else:
            full_url = f"{callback_url}?token={magic_token}"

        subject = f"{app_name} - Login Link"
        body_text, body_html = _format_magic_link_email(app_name, full_url)

        # Try outbox DB first
        outbox_db_path = self._get_setting("outbox.db_path")
        if outbox_db_path:
            mail_sender = self._get_setting("mail.mail_sender") or ""
            if mail_sender and _send_via_outbox_db(
                outbox_db_path, mail_sender, user.email, subject,
                body_text, body_html,
            ):
                self._audit_log(
                    "magic_link_sent", user.username,
                    f"Via outbox DB to {user.email}",
                )
                return True

        # Try outbox API
        outbox_url = self._get_setting("outbox.url")
        outbox_api_key = self._get_setting("outbox.api_key")
        mail_sender = self._get_setting("mail.mail_sender") or ""
        if outbox_url and outbox_api_key and mail_sender:
            if _send_via_outbox_api(
                outbox_url, outbox_api_key, mail_sender, user.email,
                subject, body_text, body_html,
            ):
                self._audit_log(
                    "magic_link_sent", user.username,
                    f"Via outbox API to {user.email}",
                )
                return True

        logger.error(
            "Email not configured (no outbox DB path or outbox API settings)"
        )
        return False


# ---------------------------------------------------------------------------
# Module-level helpers (no self needed)
# ---------------------------------------------------------------------------


def _ldap_get_attr(attrs: dict, name: str) -> str | None:
    """Extract a single-valued attribute from LDAP results."""
    values = attrs.get(name, [])
    if not values:
        return None
    val = values[0]
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _format_magic_link_email(
    app_name: str, magic_link: str
) -> tuple[str, str]:
    """Format magic link email as (text, html)."""
    body_text = (
        f"You requested to log in to {app_name}.\n\n"
        f"Click the link below to log in:\n{magic_link}\n\n"
        f"This link will expire shortly.\n\n"
        f"If you didn't request this, you can safely ignore this email.\n"
    )

    body_html = (
        '<!DOCTYPE html>\n<html>\n'
        '<head><meta charset="utf-8"></head>\n'
        '<body style="font-family: sans-serif; max-width: 600px; '
        'margin: 0 auto; padding: 20px;">\n'
        f"    <h2>Login to {app_name}</h2>\n"
        f"    <p>You requested to log in to {app_name}.</p>\n"
        f'    <p><a href="{magic_link}" '
        'style="display: inline-block; padding: 12px 24px; '
        "background: #1095c1; color: white; text-decoration: none; "
        'border-radius: 4px;">Log In</a></p>\n'
        f'    <p style="color: #666; font-size: 14px;">'
        f"Or copy this link: {magic_link}</p>\n"
        '    <p style="color: #666; font-size: 14px;">'
        "This link will expire shortly.</p>\n"
        '    <hr style="border: none; border-top: 1px solid #ddd; '
        'margin: 20px 0;">\n'
        '    <p style="color: #999; font-size: 12px;">'
        "If you didn't request this, you can safely ignore this email."
        "</p>\n"
        "</body>\n</html>"
    )

    return body_text, body_html


def _send_via_outbox_db(
    outbox_db_path: str,
    mail_sender: str,
    to_email: str,
    subject: str,
    body_text: str,
    body_html: str,
) -> bool:
    """Send email by inserting into outbox SQLite database."""
    now = datetime.now(UTC).isoformat()
    msg_uuid = str(uuid.uuid4())

    try:
        conn = apsw.Connection(outbox_db_path)
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            "INSERT INTO message "
            "(uuid, status, delivery_type, from_address, to_recipients, "
            "subject, body, body_type, source_app, created_at, updated_at) "
            "VALUES (?, 'queued', 'email', ?, ?, ?, ?, 'html', "
            "'gatekeeper', ?, ?)",
            (
                msg_uuid, mail_sender, json.dumps([to_email]),
                subject, body_html, now, now,
            ),
        )
        conn.close()
        logger.info(f"Email queued in outbox DB to {to_email}: {subject}")
        return True
    except Exception as e:
        logger.error(
            f"Failed to queue email in outbox DB to {to_email}: {e}"
        )
        return False


def _send_via_outbox_api(
    outbox_url: str,
    outbox_api_key: str,
    mail_sender: str,
    to_email: str,
    subject: str,
    body_text: str,
    body_html: str,
) -> bool:
    """Send email via outbox HTTP API."""
    try:
        import httpx
    except ImportError:
        logger.debug("httpx not installed, skipping outbox API")
        return False

    payload = {
        "from_address": mail_sender,
        "to": [to_email],
        "subject": subject,
        "body": body_html,
        "body_type": "html",
        "source_app": "gatekeeper",
    }

    try:
        resp = httpx.post(
            f"{outbox_url.rstrip('/')}/api/v1/messages",
            json=payload,
            headers={"X-API-Key": outbox_api_key},
            timeout=10.0,
        )
        if resp.status_code == 201:
            logger.info(
                f"Email queued via outbox API to {to_email}: {subject}"
            )
            return True
        logger.error(
            f"Outbox API error: {resp.status_code} - {resp.text}"
        )
        return False
    except Exception as e:
        logger.error(
            f"Failed to send email via outbox API to {to_email}: {e}"
        )
        return False
