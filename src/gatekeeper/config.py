"""Configuration registry and type system.

Every configurable setting is declared here with its key, type, default,
description, and whether it contains a secret.  The registry is the single
source of truth for what settings exist.
"""

from dataclasses import dataclass
from enum import Enum


class ConfigType(Enum):
    STRING = "string"
    INT = "int"
    BOOL = "bool"
    STRING_LIST = "string_list"


@dataclass(frozen=True, slots=True)
class ConfigEntry:
    key: str
    type: ConfigType
    default: str | int | bool | list[str]
    description: str
    secret: bool = False


# ---------------------------------------------------------------------------
# Registry -- every known setting
# ---------------------------------------------------------------------------

REGISTRY: list[ConfigEntry] = [
    # -- server --
    ConfigEntry("server.host", ConfigType.STRING, "0.0.0.0", "Bind address for production server"),
    ConfigEntry("server.port", ConfigType.INT, 5100, "Port for production server"),
    ConfigEntry("server.dev_host", ConfigType.STRING, "127.0.0.1", "Bind address for dev server"),
    ConfigEntry("server.dev_port", ConfigType.INT, 5100, "Port for dev server"),
    ConfigEntry("server.debug", ConfigType.BOOL, False, "Enable Flask debug mode"),
    ConfigEntry("server.login_url", ConfigType.STRING, "", "Public URL of Gatekeeper login page for centralised SSO"),
    # -- mail --
    ConfigEntry("mail.mail_sender", ConfigType.STRING, "", "Email sender address"),
    # -- outbox --
    ConfigEntry("outbox.db_path", ConfigType.STRING, "", "Path to outbox SQLite database"),
    ConfigEntry("outbox.url", ConfigType.STRING, "", "Outbox HTTP API base URL"),
    ConfigEntry("outbox.api_key", ConfigType.STRING, "", "Outbox API key", secret=True),
    # -- auth --
    ConfigEntry(
        "auth.magic_link_expiry_seconds", ConfigType.INT, 3600, "Magic link token lifetime"
    ),
    ConfigEntry("auth.admin_emails", ConfigType.STRING_LIST, [], "Auto-provisioned admin emails"),
    # -- proxy --
    ConfigEntry("proxy.x_forwarded_for", ConfigType.INT, 0, "Trust X-Forwarded-For (hop count)"),
    ConfigEntry(
        "proxy.x_forwarded_proto", ConfigType.INT, 0, "Trust X-Forwarded-Proto (hop count)"
    ),
    ConfigEntry("proxy.x_forwarded_host", ConfigType.INT, 0, "Trust X-Forwarded-Host (hop count)"),
    ConfigEntry(
        "proxy.x_forwarded_prefix", ConfigType.INT, 0, "Trust X-Forwarded-Prefix (hop count)"
    ),
    # -- ldap --
    ConfigEntry("ldap.enabled", ConfigType.BOOL, False, "Enable LDAP authentication"),
    ConfigEntry("ldap.domains", ConfigType.STRING_LIST, [], "Comma-separated LDAP domain names"),
]

# Template entries for per-domain LDAP settings.  The placeholder {domain}
# is replaced with each domain name from ldap.domains.
LDAP_DOMAIN_TEMPLATE: list[ConfigEntry] = [
    ConfigEntry("ldap.{domain}.server", ConfigType.STRING, "", "LDAP server URI"),
    ConfigEntry("ldap.{domain}.base_dn", ConfigType.STRING, "", "LDAP search base DN"),
    ConfigEntry("ldap.{domain}.bind_dn", ConfigType.STRING, "", "LDAP bind DN"),
    ConfigEntry(
        "ldap.{domain}.bind_password", ConfigType.STRING, "", "LDAP bind password", secret=True
    ),
    ConfigEntry(
        "ldap.{domain}.user_filter",
        ConfigType.STRING,
        "(&(objectClass=user)(sAMAccountName={username}))",
        "LDAP filter for username lookup",
    ),
    ConfigEntry("ldap.{domain}.email_attr", ConfigType.STRING, "mail", "LDAP attribute for email"),
    ConfigEntry(
        "ldap.{domain}.email_filter",
        ConfigType.STRING,
        "",
        "LDAP filter for email lookup (empty = auto from email_attr)",
    ),
    ConfigEntry(
        "ldap.{domain}.fullname_attr",
        ConfigType.STRING,
        "displayName",
        "LDAP attribute for full name",
    ),
    ConfigEntry(
        "ldap.{domain}.username_attr",
        ConfigType.STRING,
        "sAMAccountName",
        "LDAP attribute for username",
    ),
]

# Fast lookup by key
_REGISTRY_MAP: dict[str, ConfigEntry] = {e.key: e for e in REGISTRY}


def resolve_entry(key: str) -> ConfigEntry | None:
    """Look up a registry entry by key.

    Handles both static registry entries and dynamic per-domain LDAP keys
    like ``ldap.CORP.server``.
    """
    entry = _REGISTRY_MAP.get(key)
    if entry is not None:
        return entry

    # Check if this is a per-domain LDAP key: ldap.<domain>.<field>
    parts = key.split(".")
    if len(parts) == 3 and parts[0] == "ldap":
        template_key = f"ldap.{{domain}}.{parts[2]}"
        for tmpl in LDAP_DOMAIN_TEMPLATE:
            if tmpl.key == template_key:
                return ConfigEntry(
                    key=key,
                    type=tmpl.type,
                    default=tmpl.default,
                    description=tmpl.description.replace("{domain}", parts[1]),
                    secret=tmpl.secret,
                )
    return None


def expand_ldap_entries(domains: list[str]) -> list[ConfigEntry]:
    """Expand LDAP domain template entries for the given domain names."""
    entries = []
    for domain in domains:
        for tmpl in LDAP_DOMAIN_TEMPLATE:
            entries.append(
                ConfigEntry(
                    key=tmpl.key.replace("{domain}", domain),
                    type=tmpl.type,
                    default=tmpl.default,
                    description=tmpl.description,
                    secret=tmpl.secret,
                )
            )
    return entries


# ---------------------------------------------------------------------------
# Value parsing / serialization
# ---------------------------------------------------------------------------


def parse_value(entry: ConfigEntry, raw: str) -> str | int | bool | list[str]:
    """Parse a raw string value according to the entry's type."""
    match entry.type:
        case ConfigType.STRING:
            return raw
        case ConfigType.INT:
            return int(raw)
        case ConfigType.BOOL:
            return raw.lower() in ("true", "1", "yes", "on")
        case ConfigType.STRING_LIST:
            return [s.strip() for s in raw.split(",") if s.strip()]


def serialize_value(entry: ConfigEntry, value: str | int | bool | list[str]) -> str:
    """Serialize a typed value to a string for storage."""
    match entry.type:
        case ConfigType.BOOL:
            return "true" if value else "false"
        case ConfigType.STRING_LIST:
            if isinstance(value, list):
                return ", ".join(value)
            return str(value)
        case _:
            return str(value)


# ---------------------------------------------------------------------------
# Mapping from registry keys to Flask app.config keys
# ---------------------------------------------------------------------------

KEY_MAP: dict[str, str] = {
    "server.host": "HOST",
    "server.port": "PORT",
    "server.dev_host": "DEV_HOST",
    "server.dev_port": "DEV_PORT",
    "server.debug": "DEBUG",
    "mail.mail_sender": "MAIL_SENDER",
    "outbox.db_path": "OUTBOX_DB_PATH",
    "outbox.url": "OUTBOX_URL",
    "outbox.api_key": "OUTBOX_API_KEY",
    "auth.magic_link_expiry_seconds": "MAGIC_LINK_EXPIRY_SECONDS",
    "auth.admin_emails": "ADMIN_EMAILS",
    "proxy.x_forwarded_for": "PROXY_X_FORWARDED_FOR",
    "proxy.x_forwarded_proto": "PROXY_X_FORWARDED_PROTO",
    "proxy.x_forwarded_host": "PROXY_X_FORWARDED_HOST",
    "proxy.x_forwarded_prefix": "PROXY_X_FORWARDED_PREFIX",
    "server.login_url": "LOGIN_URL",
    "ldap.enabled": "LDAP_ENABLED",
    "ldap.domains": "LDAP_DOMAINS",
}


def flask_key_for_ldap_domain(domain: str, field: str) -> str:
    """Return the Flask config key for a per-domain LDAP setting.

    E.g. flask_key_for_ldap_domain("CORP", "server") -> "LDAP_CORP_SERVER"
    """
    return f"LDAP_{domain}_{field.upper()}"


# ---------------------------------------------------------------------------
# INI section/key -> registry key mapping (for config import)
# ---------------------------------------------------------------------------

INI_MAP: dict[tuple[str, str], str | None] = {
    ("server", "HOST"): "server.host",
    ("server", "PORT"): "server.port",
    ("server", "DEV_HOST"): "server.dev_host",
    ("server", "DEV_PORT"): "server.dev_port",
    ("server", "DEBUG"): "server.debug",
    ("database", "PATH"): None,  # handled specially -- not a config setting
    ("mail", "MAIL_SENDER"): "mail.mail_sender",
    ("outbox", "DB_PATH"): "outbox.db_path",
    ("outbox", "URL"): "outbox.url",
    ("outbox", "API_KEY"): "outbox.api_key",
    ("auth", "MAGIC_LINK_EXPIRY_SECONDS"): "auth.magic_link_expiry_seconds",
    ("auth", "ADMIN_EMAILS"): "auth.admin_emails",
    ("proxy", "X_FORWARDED_FOR"): "proxy.x_forwarded_for",
    ("proxy", "X_FORWARDED_PROTO"): "proxy.x_forwarded_proto",
    ("proxy", "X_FORWARDED_HOST"): "proxy.x_forwarded_host",
    ("proxy", "X_FORWARDED_PREFIX"): "proxy.x_forwarded_prefix",
    ("server", "LOGIN_URL"): "server.login_url",
    ("ldap", "ENABLED"): "ldap.enabled",
    ("ldap", "DOMAINS"): "ldap.domains",
}

# Per-domain LDAP INI field -> registry field suffix
LDAP_INI_FIELDS: dict[str, str] = {
    "SERVER": "server",
    "BASE_DN": "base_dn",
    "BIND_DN": "bind_dn",
    "BIND_PASSWORD": "bind_password",
    "USER_FILTER": "user_filter",
    "EMAIL_ATTR": "email_attr",
    "EMAIL_FILTER": "email_filter",
    "FULLNAME_ATTR": "fullname_attr",
    "USERNAME_ATTR": "username_attr",
}
