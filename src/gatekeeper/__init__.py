"""Gatekeeper - Shared Authentication Service."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
        ADMIN_USERNAMES=[],
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

    @app.cli.command("ensure-admins")
    def ensure_admins_command() -> None:
        """Ensure ADMIN_USERNAMES from config are in the admin group."""
        _ensure_admins(app)

    # Register blueprints
    from gatekeeper.blueprints import (
        admin_api_keys,
        admin_groups,
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

    # Jinja filters
    @app.template_filter("localdate")
    def localdate_filter(iso_string: str | None) -> str:
        if not iso_string:
            return ""
        try:
            dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.strftime("%b %d, %Y")
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
            return dt.strftime("%b %d, %Y %H:%M UTC")
        except Exception:
            return iso_string[:19] if iso_string else ""

    @app.template_filter("tojson_pretty")
    def tojson_pretty_filter(value: Any) -> str:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return str(value)
        return json.dumps(value, indent=2)

    # Ensure admin users on first request
    with app.app_context():
        from gatekeeper.services.ldap_service import check_ldap_configured

        check_ldap_configured()

    return app


def _ensure_admins(app: Flask) -> None:
    """Ensure configured admin usernames exist and are in the admin group."""
    from gatekeeper.models.group import Group
    from gatekeeper.models.user import User

    admin_usernames = app.config.get("ADMIN_USERNAMES", [])
    for username in admin_usernames:
        user = User.get(username)
        if user and not Group.user_in_group(username, "admin"):
            Group.get("admin").add_member(username)
            app.logger.info(f"Added existing user {username} to admin group")
