"""CLI entry point for gatekeeper-admin."""

import configparser
import os
import stat
import sys
from datetime import UTC, datetime

import click
from flask import Flask

from gatekeeper.config import (
    INI_MAP,
    LDAP_INI_FIELDS,
    REGISTRY,
    expand_ldap_entries,
    parse_value,
    resolve_entry,
    serialize_value,
)
from gatekeeper.db import (
    close_standalone_db,
    get_db_path,
    get_standalone_db,
    init_db_at,
    standalone_transaction,
)


def _make_app() -> Flask:
    """Create a Flask app for commands that need app context."""
    from gatekeeper import create_app

    return create_app()


# ---------------------------------------------------------------------------
# Config helpers (standalone DB, no Flask)
# ---------------------------------------------------------------------------


def _db_get(key: str) -> str | None:
    """Read a single value from app_setting."""
    db = get_standalone_db()
    row = db.execute("SELECT value FROM app_setting WHERE key = ?", (key,)).fetchone()
    return str(row[0]) if row else None


def _db_get_all() -> dict[str, str]:
    """Read all app_setting rows into a dict."""
    db = get_standalone_db()
    rows = db.execute("SELECT key, value FROM app_setting ORDER BY key").fetchall()
    return {str(r[0]): str(r[1]) for r in rows}


def _db_set(key: str, value: str) -> None:
    """Upsert a value into app_setting."""
    with standalone_transaction() as cursor:
        cursor.execute(
            "INSERT INTO app_setting (key, value, description) VALUES (?, ?, '') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.group()
def main():
    """Gatekeeper administration tool."""


# ---- config group --------------------------------------------------------


@main.group()
def config():
    """View and manage configuration settings."""


@config.command("list")
def config_list():
    """Show all settings with their effective values."""
    db_values = _db_get_all()

    # Determine LDAP domains for expanding template entries
    domains_raw = db_values.get("ldap.domains", "")
    domains = [d.strip() for d in domains_raw.split(",") if d.strip()] if domains_raw else []

    all_entries = list(REGISTRY)
    if domains:
        all_entries.extend(expand_ldap_entries(domains))

    current_group = ""
    for entry in all_entries:
        group = entry.key.split(".")[0]
        if group != current_group:
            if current_group:
                click.echo()
            click.echo(click.style(f"[{group}]", bold=True))
            current_group = group

        raw = db_values.get(entry.key)
        if raw is not None:
            value = raw
            source = "db"
        else:
            value = serialize_value(entry, entry.default)
            source = "default"

        if entry.secret and raw is not None:
            display = "********"
        else:
            display = value if value else "(empty)"

        source_tag = click.style(f"[{source}]", fg="cyan" if source == "db" else "yellow")
        click.echo(f"  {entry.key} = {display}  {source_tag}")
        click.echo(click.style(f"    {entry.description}", dim=True))

    close_standalone_db()


@config.command("get")
@click.argument("key")
def config_get(key: str):
    """Get the effective value of a setting."""
    entry = resolve_entry(key)
    if not entry:
        click.echo(f"Unknown setting: {key}", err=True)
        sys.exit(1)
    assert entry is not None

    raw = _db_get(key)
    if raw is not None:
        value = parse_value(entry, raw)
    else:
        value = entry.default

    if entry.secret and raw is not None:
        click.echo("********")
    elif isinstance(value, list):
        click.echo(", ".join(value) if value else "(empty)")
    elif isinstance(value, bool):
        click.echo("true" if value else "false")
    else:
        click.echo(value if value else "(empty)")

    close_standalone_db()


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """Set a configuration value in the database."""
    entry = resolve_entry(key)
    if not entry:
        click.echo(f"Unknown setting: {key}", err=True)
        sys.exit(1)
    assert entry is not None

    # Validate by parsing
    try:
        parse_value(entry, value)
    except (ValueError, TypeError) as exc:
        click.echo(f"Invalid value for {key} ({entry.type.value}): {exc}", err=True)
        sys.exit(1)

    _db_set(key, value)
    click.echo(f"{key} = {value}")
    close_standalone_db()


@config.command("export")
@click.argument("output_file", type=click.Path())
def config_export(output_file: str):
    """Export all settings as a shell script of make config-set calls."""
    db_values = _db_get_all()

    # Determine LDAP domains for expanding template entries
    domains_raw = db_values.get("ldap.domains", "")
    domains = [d.strip() for d in domains_raw.split(",") if d.strip()] if domains_raw else []

    all_entries = list(REGISTRY)
    if domains:
        all_entries.extend(expand_ldap_entries(domains))

    lines = [
        "#!/bin/bash",
        "# Configuration export for Gatekeeper",
        f"# Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
    ]

    for entry in all_entries:
        raw = db_values.get(entry.key)
        if raw is not None:
            value = raw
            lines.append(f"make config-set KEY={entry.key} VAL='{value}'")
        else:
            value = serialize_value(entry, entry.default)
            lines.append(f"# default: {entry.key}")
            lines.append(f"# make config-set KEY={entry.key} VAL='{value}'")

    with open(output_file, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(output_file, os.stat(output_file).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    click.echo(f"Exported {len(all_entries)} settings to {output_file}")
    close_standalone_db()


@config.command("import")
@click.argument("ini_file", type=click.Path(exists=True))
def config_import(ini_file: str):
    """Import settings from an INI config file."""
    cfg = configparser.ConfigParser()
    cfg.read(ini_file)

    imported = 0

    for section in cfg.sections():
        # Check for LDAP domain sections like [ldap.CORP]
        if section.startswith("ldap.") and section != "ldap":
            domain = section.split(".", 1)[1]
            for ini_key, value in cfg.items(section):
                field = ini_key.upper()
                if field in LDAP_INI_FIELDS:
                    registry_key = f"ldap.{domain}.{LDAP_INI_FIELDS[field]}"
                    _db_set(registry_key, value)
                    click.echo(f"  {registry_key} = {value}")
                    imported += 1
            continue

        for ini_key, value in cfg.items(section):
            # Skip configparser's DEFAULT entries
            if ini_key == "__name__":
                continue
            lookup = (section, ini_key.upper())
            registry_key = INI_MAP.get(lookup)
            if registry_key is None:
                if lookup in INI_MAP:
                    # Explicitly skipped (e.g. database.PATH)
                    click.echo(f"  (skip) [{section}] {ini_key}")
                else:
                    click.echo(f"  (unknown) [{section}] {ini_key}")
                continue
            _db_set(registry_key, value)
            click.echo(f"  {registry_key} = {value}")
            imported += 1

    click.echo(f"\nImported {imported} settings.")
    close_standalone_db()


# ---- admin commands ------------------------------------------------------


@main.command("init-db")
def init_db_command():
    """Initialize the database schema."""
    db_path = get_db_path()
    init_db_at(db_path)
    click.echo("Database initialized.")


@main.command("create-admin")
@click.argument("username")
@click.argument("email")
@click.option("--fullname", default="", help="User's full name")
def create_admin_command(username: str, email: str, fullname: str):
    """Create an admin user and add them to the admin group."""
    app = _make_app()
    with app.app_context():
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


@main.command("import-users")
@click.argument("csv_file", type=click.Path(exists=True))
def import_users_command(csv_file: str):
    """Import users from a CSV file (columns: username,email,fullname)."""
    import csv
    from datetime import UTC, datetime

    app = _make_app()
    with app.app_context():
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


@main.command("ensure-admins")
def ensure_admins_command():
    """Ensure ADMIN_EMAILS from config have accounts and are in the admin group."""
    app = _make_app()
    with app.app_context():
        from gatekeeper import _ensure_admins

        _ensure_admins(app)
    click.echo("Admin accounts ensured.")


@main.command("generate-api-key")
@click.option("--description", "-d", default="", help="Description for the API key")
def generate_api_key_command(description: str):
    """Generate a new API key and print it to the console."""
    app = _make_app()
    with app.app_context():
        from gatekeeper.models.api_key import ApiKey

        api_key = ApiKey.generate(description=description)
        click.echo(api_key.key)
