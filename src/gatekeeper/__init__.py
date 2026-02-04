"""Gatekeeper - Shared Authentication Service."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import click
from flask import Flask

from gatekeeper.config import load_config


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Application factory for Gatekeeper."""
    if "GATEKEEPER_ROOT" in os.environ:
        project_root = Path(os.environ["GATEKEEPER_ROOT"])
    else:
        source_root = Path(__file__).parent.parent.parent
        if (source_root / "src" / "gatekeeper" / "__init__.py").exists():
            project_root = source_root
        else:
            project_root = Path.cwd()

    instance_path = project_root / "instance"

    app = Flask(__name__, instance_path=str(instance_path), instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE_PATH=str(instance_path / "gatekeeper.sqlite3"),
        MAGIC_LINK_EXPIRY_SECONDS=3600,
        HOST="0.0.0.0",
        PORT=5100,
        DEV_HOST="127.0.0.1",
        DEV_PORT=5100,
        DEBUG=False,
        LDAP_ENABLED=False,
        ADMIN_EMAILS=[],
    )

    if test_config is None:
        load_config(app, instance_path, project_root)
    else:
        app.config.from_mapping(test_config)

    instance_path.mkdir(parents=True, exist_ok=True)

    from gatekeeper.db import close_db, init_db_command

    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.argument("email")
    @click.option("--fullname", default="", help="User's full name")
    def create_admin_command(username: str, email: str, fullname: str) -> None:
        """Create an admin user and add them to the admin group."""
        from gatekeeper.models.group import Group
        from gatekeeper.models.user import User

        user = User.get(username)
        if user:
            click.echo(f"User {username} already exists.")
        else:
            user = User.create(username=username, email=email, fullname=fullname)
            click.echo(f"Created user: {username}")

        if Group.user_in_group(username, "admin"):
            click.echo(f"User {username} is already in admin group.")
        else:
            group = Group.get("admin")
            if group:
                group.add_member(username)
                click.echo(f"Added {username} to admin group.")

    @app.cli.command("import-users")
    @click.argument("csv_file", type=click.Path(exists=True))
    def import_users_command(csv_file: str) -> None:
        """Import users from a CSV file (columns: username,email,fullname)."""
        import csv

        from gatekeeper.db import get_db
        from gatekeeper.models.group import Group
        from gatekeeper.models.user import User

        standard_group = Group.get("standard")
        db = get_db()
        now = datetime.now(UTC).isoformat()

        created = 0
        skipped = 0
        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                username = row.get("username", "").strip()
                email = row.get("email", "").strip()
                fullname = row.get("fullname", "").strip()

                if not username or not email:
                    click.echo(f"Skipping row (missing username or email): {row}")
                    skipped += 1
                    continue

                if User.get(username):
                    click.echo(f"Exists, skipping: {username}")
                    skipped += 1
                    continue

                User.create(username=username, email=email, fullname=fullname)
                if standard_group:
                    standard_group.add_member(username)
                db.execute(
                    "INSERT INTO audit_log (timestamp, actor, action, target, details) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        now,
                        "import-users",
                        "user_created",
                        username,
                        f"email={email}, fullname={fullname}",
                    ),
                )
                click.echo(f"Created: {username}")
                created += 1

        click.echo(f"Done. Created: {created}, Skipped: {skipped}")

    @app.cli.command("ensure-admins")
    def ensure_admins_command() -> None:
        """Ensure ADMIN_EMAILS from config have accounts and are in the admin group."""
        _ensure_admins(app)

    # Register blueprints
    from gatekeeper.blueprints import (
        admin_api_keys,
        admin_groups,
        admin_sql,
        admin_system,
        admin_users,
        api,
        auth,
    )

    app.register_blueprint(auth.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(admin_users.bp)
    app.register_blueprint(admin_groups.bp)
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
    def index():
        from flask import redirect, url_for

        return redirect(url_for("admin_system.index"))

    # Startup checks
    with app.app_context():
        from gatekeeper.services.ldap_service import check_ldap_configured

        check_ldap_configured()
        _ensure_admins(app)

    return app


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
