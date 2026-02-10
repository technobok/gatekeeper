"""Gatekeeper - Shared Authentication Service."""

from gatekeeper.client import GatekeeperClient

__all__ = ["GatekeeperClient", "create_app"]

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import apsw
from flask import Flask
from werkzeug.wrappers import Response

from gatekeeper.config import (
    KEY_MAP,
    REGISTRY,
    expand_ldap_entries,
    flask_key_for_ldap_domain,
    parse_value,
)


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Application factory for Gatekeeper."""
    # Resolve database path
    db_path = os.environ.get("GATEKEEPER_DB")
    if not db_path:
        # Fallback: project root detection for local development
        if "GATEKEEPER_ROOT" in os.environ:
            project_root = Path(os.environ["GATEKEEPER_ROOT"])
        else:
            source_root = Path(__file__).parent.parent.parent
            if (source_root / "src" / "gatekeeper" / "__init__.py").exists():
                project_root = source_root
            else:
                project_root = Path.cwd()
        db_path = str(project_root / "instance" / "gatekeeper.sqlite3")
        instance_path = project_root / "instance"
    else:
        instance_path = Path(db_path).parent

    instance_path.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__, instance_path=str(instance_path), instance_relative_config=True)

    # Minimal defaults before DB config is loaded
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE_PATH=db_path,
    )

    if test_config is not None:
        app.config.from_mapping(test_config)
    else:
        _load_config_from_db(app)

    # Allow MAIL_SENDER from environment
    if not app.config.get("MAIL_SENDER"):
        app.config["MAIL_SENDER"] = os.environ.get("MAIL_SENDER", "")

    from gatekeeper.db import close_db

    app.teardown_appcontext(close_db)

    # Register blueprints
    from gatekeeper.blueprints import (
        admin_api_keys,
        admin_groups,
        admin_sql,
        admin_system,
        admin_user_properties,
        admin_users,
        api,
        auth,
    )

    app.register_blueprint(auth.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(admin_users.bp)
    app.register_blueprint(admin_groups.bp)
    app.register_blueprint(admin_user_properties.bp)
    app.register_blueprint(admin_api_keys.bp)
    app.register_blueprint(admin_system.bp)
    app.register_blueprint(admin_sql.bp)

    # Jinja filters
    def _get_user_timezone() -> ZoneInfo:
        """Get user's timezone from request header or cookie."""
        from flask import request

        tz_name = request.headers.get("X-Timezone") or request.cookies.get("tz") or "UTC"
        try:
            return ZoneInfo(tz_name)
        except Exception:
            return ZoneInfo("UTC")

    @app.template_filter("localdate")
    def localdate_filter(iso_string: str | None) -> str:
        if not iso_string:
            return ""
        try:
            dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            user_tz = _get_user_timezone()
            local_dt = dt.astimezone(user_tz)
            return local_dt.strftime("%b %d, %Y")
        except Exception:
            return iso_string[:10] if iso_string else ""

    @app.template_filter("localdatetime")
    def localdatetime_filter(iso_string: str | None) -> str:
        if not iso_string:
            return ""
        try:
            dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            user_tz = _get_user_timezone()
            local_dt = dt.astimezone(user_tz)
            tz_abbr = local_dt.strftime("%Z")
            return local_dt.strftime(f"%b %d, %Y %H:%M {tz_abbr}")
        except Exception:
            return iso_string[:16].replace("T", " ") if iso_string else ""

    @app.template_filter("tojson_pretty")
    def tojson_pretty_filter(value: Any) -> str:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return str(value)
        return json.dumps(value, indent=2)

    # Root route redirects to admin
    @app.route("/")
    def index() -> Response:
        from flask import redirect, url_for

        return redirect(url_for("admin_system.index"))

    # Startup checks
    with app.app_context():
        from gatekeeper.db import migrate_db
        from gatekeeper.services.ldap_service import check_ldap_configured

        migrate_db()
        check_ldap_configured()
        _ensure_admins(app)

    return app


def _load_config_from_db(app: Flask) -> None:
    """Load configuration from the database into Flask app.config."""
    db_path = app.config["DATABASE_PATH"]

    try:
        conn = apsw.Connection(db_path, flags=apsw.SQLITE_OPEN_READONLY)
    except apsw.CantOpenError:
        # Database doesn't exist yet (init-db hasn't been run)
        return

    try:
        rows = conn.execute("SELECT key, value FROM app_setting").fetchall()
    except apsw.SQLError:
        # Table doesn't exist yet
        conn.close()
        return

    db_values = {str(r[0]): str(r[1]) for r in rows}
    conn.close()

    # Load SECRET_KEY from database
    if "secret_key" in db_values:
        app.config["SECRET_KEY"] = db_values["secret_key"]

    # Apply registry entries
    for entry in REGISTRY:
        flask_key = KEY_MAP.get(entry.key)
        if not flask_key:
            continue

        raw = db_values.get(entry.key)
        if raw is not None:
            value = parse_value(entry, raw)
        else:
            value = entry.default

        app.config[flask_key] = value

    # Apply LDAP per-domain entries
    domains = app.config.get("LDAP_DOMAINS", [])
    if domains:
        for domain_entry in expand_ldap_entries(domains):
            raw = db_values.get(domain_entry.key)
            if raw is not None:
                value = parse_value(domain_entry, raw)
            else:
                value = domain_entry.default

            # Extract field name: ldap.CORP.server -> server
            field = domain_entry.key.split(".", 2)[2]
            domain = domain_entry.key.split(".", 2)[1]

            # Build email_filter default if empty and email_attr is available
            if field == "email_filter" and not value:
                email_attr = app.config.get(flask_key_for_ldap_domain(domain, "email_attr"), "mail")
                value = f"(&(objectClass=user)({email_attr}={{email}}))"

            app.config[flask_key_for_ldap_domain(domain, field)] = value

    # Apply ProxyFix if any proxy values are non-zero
    x_for = app.config.get("PROXY_X_FORWARDED_FOR", 0)
    x_proto = app.config.get("PROXY_X_FORWARDED_PROTO", 0)
    x_host = app.config.get("PROXY_X_FORWARDED_HOST", 0)
    x_prefix = app.config.get("PROXY_X_FORWARDED_PREFIX", 0)
    if any((x_for, x_proto, x_host, x_prefix)):
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(  # type: ignore[assignment]
            app.wsgi_app, x_for=x_for, x_proto=x_proto, x_host=x_host, x_prefix=x_prefix
        )


def _ensure_admins(app: Flask) -> None:
    """Ensure configured admin emails have accounts and are in the admin group."""
    from gatekeeper.db import get_db
    from gatekeeper.models.group import Group
    from gatekeeper.models.user import User

    admin_emails = app.config.get("ADMIN_EMAILS", [])
    if not admin_emails:
        return

    # Check if the database is initialized (schema exists)
    db = get_db()
    try:
        db.execute("SELECT 1 FROM user LIMIT 0").fetchone()
    except Exception:
        return

    for email in admin_emails:
        users = User.get_by_email(email)
        if users:
            user = users[0]
        else:
            user = User.create(username=email, email=email)
            app.logger.info(f"Created admin user: {email}")

        if not Group.user_in_group(user.username, "admin"):
            admin_group = Group.get("admin")
            if admin_group:
                admin_group.add_member(user.username)
                app.logger.info(f"Added {user.username} to admin group")
