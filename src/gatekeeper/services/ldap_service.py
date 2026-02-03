"""LDAP lookup service (optional)."""

from dataclasses import dataclass

from flask import current_app


@dataclass
class LdapUser:
    username: str  # domain\sAMAccountName
    email: str
    fullname: str


def is_ldap_available() -> bool:
    """Check if python-ldap is installed."""
    try:
        import ldap  # noqa: F401

        return True
    except ImportError:
        return False


def is_ldap_enabled() -> bool:
    """Check if LDAP is enabled in configuration."""
    return current_app.config.get("LDAP_ENABLED", False)


def check_ldap_configured() -> None:
    """Raise RuntimeError if LDAP is enabled but python-ldap is not installed."""
    if is_ldap_enabled() and not is_ldap_available():
        raise RuntimeError(
            "LDAP is enabled in configuration but python-ldap is not installed. "
            "Install it with: pip install gatekeeper[ldap]"
        )


def lookup_by_username(domain: str, username: str) -> LdapUser | None:
    """Look up a user by username in the specified LDAP domain."""
    if not is_ldap_enabled() or not is_ldap_available():
        return None

    import ldap

    server = current_app.config.get(f"LDAP_{domain}_SERVER")
    base_dn = current_app.config.get(f"LDAP_{domain}_BASE_DN")
    bind_dn = current_app.config.get(f"LDAP_{domain}_BIND_DN", "")
    bind_password = current_app.config.get(f"LDAP_{domain}_BIND_PASSWORD", "")
    user_filter = current_app.config.get(
        f"LDAP_{domain}_USER_FILTER",
        "(&(objectClass=user)(sAMAccountName={username}))",
    )
    email_attr = current_app.config.get(f"LDAP_{domain}_EMAIL_ATTR", "mail")
    fullname_attr = current_app.config.get(f"LDAP_{domain}_FULLNAME_ATTR", "displayName")
    username_attr = current_app.config.get(f"LDAP_{domain}_USERNAME_ATTR", "sAMAccountName")

    if not server or not base_dn:
        return None

    search_filter = user_filter.replace("{username}", ldap.filter.escape_filter_chars(username))

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

            email = _get_attr(attrs, email_attr)
            fullname = _get_attr(attrs, fullname_attr) or ""
            sam = _get_attr(attrs, username_attr) or username

            if not email:
                continue

            return LdapUser(
                username=f"{domain}\\{sam}",
                email=email,
                fullname=fullname,
            )

    except Exception as e:
        current_app.logger.error(f"LDAP lookup failed for {domain}\\{username}: {e}")

    return None


def lookup_by_email(email: str) -> LdapUser | None:
    """Look up a user by email across all configured LDAP domains."""
    if not is_ldap_enabled() or not is_ldap_available():
        return None

    import ldap

    domains = current_app.config.get("LDAP_DOMAINS", [])

    for domain in domains:
        server = current_app.config.get(f"LDAP_{domain}_SERVER")
        base_dn = current_app.config.get(f"LDAP_{domain}_BASE_DN")
        bind_dn = current_app.config.get(f"LDAP_{domain}_BIND_DN", "")
        bind_password = current_app.config.get(f"LDAP_{domain}_BIND_PASSWORD", "")
        email_attr = current_app.config.get(f"LDAP_{domain}_EMAIL_ATTR", "mail")
        fullname_attr = current_app.config.get(f"LDAP_{domain}_FULLNAME_ATTR", "displayName")
        username_attr = current_app.config.get(f"LDAP_{domain}_USERNAME_ATTR", "sAMAccountName")

        if not server or not base_dn:
            continue

        search_filter = (
            f"(&(objectClass=user)({email_attr}={ldap.filter.escape_filter_chars(email)}))"
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

                fullname = _get_attr(attrs, fullname_attr) or ""
                sam = _get_attr(attrs, username_attr)

                if not sam:
                    continue

                return LdapUser(
                    username=f"{domain}\\{sam}",
                    email=email,
                    fullname=fullname,
                )

        except Exception as e:
            current_app.logger.error(f"LDAP email lookup failed in {domain}: {e}")

    return None


def _get_attr(attrs: dict, name: str) -> str | None:
    """Extract a single-valued attribute from LDAP results."""
    values = attrs.get(name, [])
    if not values:
        return None
    val = values[0]
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)
