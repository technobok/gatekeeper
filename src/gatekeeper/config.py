"""Configuration loading helpers."""

import configparser
from pathlib import Path


def load_config(app, instance_path: Path, project_root: Path) -> None:
    """Load configuration from config.ini into Flask app config."""
    config_path = instance_path / "config.ini"
    if not config_path.exists():
        config_path = project_root / "config.ini"

    if not config_path.exists():
        return

    config = configparser.ConfigParser()
    config.read(config_path)

    if config.has_section("server"):
        if config.has_option("server", "HOST"):
            app.config["HOST"] = config.get("server", "HOST")
        if config.has_option("server", "PORT"):
            app.config["PORT"] = config.getint("server", "PORT")
        if config.has_option("server", "DEV_HOST"):
            app.config["DEV_HOST"] = config.get("server", "DEV_HOST")
        if config.has_option("server", "DEV_PORT"):
            app.config["DEV_PORT"] = config.getint("server", "DEV_PORT")
        if config.has_option("server", "DEBUG"):
            app.config["DEBUG"] = config.getboolean("server", "DEBUG")

    if config.has_section("database"):
        if config.has_option("database", "PATH"):
            db_path = config.get("database", "PATH")
            if not Path(db_path).is_absolute():
                db_path = str(project_root / db_path)
            app.config["DATABASE_PATH"] = db_path

    if config.has_section("mail"):
        app.config["SMTP_SERVER"] = config.get("mail", "SMTP_SERVER", fallback="")
        app.config["SMTP_PORT"] = config.getint("mail", "SMTP_PORT", fallback=587)
        app.config["SMTP_USE_TLS"] = config.getboolean("mail", "SMTP_USE_TLS", fallback=True)
        app.config["SMTP_USERNAME"] = config.get("mail", "SMTP_USERNAME", fallback="")
        app.config["SMTP_PASSWORD"] = config.get("mail", "SMTP_PASSWORD", fallback="")
        app.config["MAIL_SENDER"] = config.get("mail", "MAIL_SENDER", fallback="")

    if config.has_section("auth"):
        if config.has_option("auth", "MAGIC_LINK_EXPIRY_SECONDS"):
            app.config["MAGIC_LINK_EXPIRY_SECONDS"] = config.getint(
                "auth", "MAGIC_LINK_EXPIRY_SECONDS"
            )
        if config.has_option("auth", "ADMIN_EMAILS"):
            raw = config.get("auth", "ADMIN_EMAILS")
            app.config["ADMIN_EMAILS"] = [u.strip() for u in raw.split(",") if u.strip()]

    if config.has_section("proxy"):
        from werkzeug.middleware.proxy_fix import ProxyFix

        x_for = config.getint("proxy", "X_FORWARDED_FOR", fallback=1)
        x_proto = config.getint("proxy", "X_FORWARDED_PROTO", fallback=1)
        x_host = config.getint("proxy", "X_FORWARDED_HOST", fallback=1)
        x_prefix = config.getint("proxy", "X_FORWARDED_PREFIX", fallback=0)
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=x_for, x_proto=x_proto, x_host=x_host, x_prefix=x_prefix
        )

    if config.has_section("ldap"):
        app.config["LDAP_ENABLED"] = config.getboolean("ldap", "ENABLED", fallback=False)
        if app.config["LDAP_ENABLED"]:
            domains_raw = config.get("ldap", "DOMAINS", fallback="")
            domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
            app.config["LDAP_DOMAINS"] = domains
            for domain in domains:
                section = f"ldap.{domain}"
                if config.has_section(section):
                    app.config[f"LDAP_{domain}_SERVER"] = config.get(section, "SERVER")
                    app.config[f"LDAP_{domain}_BASE_DN"] = config.get(section, "BASE_DN")
                    app.config[f"LDAP_{domain}_BIND_DN"] = config.get(
                        section, "BIND_DN", fallback=""
                    )
                    app.config[f"LDAP_{domain}_BIND_PASSWORD"] = config.get(
                        section, "BIND_PASSWORD", fallback=""
                    )
                    app.config[f"LDAP_{domain}_USER_FILTER"] = config.get(
                        section,
                        "USER_FILTER",
                        fallback="(&(objectClass=user)(sAMAccountName={username}))",
                    )
                    app.config[f"LDAP_{domain}_EMAIL_ATTR"] = config.get(
                        section, "EMAIL_ATTR", fallback="mail"
                    )
                    email_attr = app.config[f"LDAP_{domain}_EMAIL_ATTR"]
                    app.config[f"LDAP_{domain}_EMAIL_FILTER"] = config.get(
                        section,
                        "EMAIL_FILTER",
                        fallback=f"(&(objectClass=user)({email_attr}={{email}}))",
                    )
                    app.config[f"LDAP_{domain}_FULLNAME_ATTR"] = config.get(
                        section, "FULLNAME_ATTR", fallback="displayName"
                    )
                    app.config[f"LDAP_{domain}_USERNAME_ATTR"] = config.get(
                        section, "USERNAME_ATTR", fallback="sAMAccountName"
                    )
    else:
        app.config["LDAP_ENABLED"] = False
