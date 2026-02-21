"""LDAP lookup service (optional)."""

from dataclasses import dataclass

from flask import current_app


@dataclass
class LdapUser:
    username: str  # domain\sAMAccountName
    email: str
    fullname: str
    given_name: str = ""
    mail_nickname: str = ""
    title: str = ""
    department: str = ""
    manager: str = ""
    telephone_number: str = ""
    mobile_number: str = ""
    groups: list[str] | None = None

    def __post_init__(self) -> None:
        if self.groups is None:
            self.groups = []


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
        current_app.logger.debug(
            f"LDAP lookup skipped: enabled={is_ldap_enabled()}, available={is_ldap_available()}"
        )
        return None

    import ldap
    import ldap.filter

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

    current_app.logger.debug(f"LDAP lookup: domain={domain}, server={server}, base_dn={base_dn}")

    if not server or not base_dn:
        current_app.logger.warning(
            f"LDAP config missing for domain {domain}: server={server}, base_dn={base_dn}"
        )
        return None

    search_filter = user_filter.replace("{username}", ldap.filter.escape_filter_chars(username))
    current_app.logger.debug(f"LDAP search filter: {search_filter}")

    try:
        conn = ldap.initialize(server)
        conn.set_option(ldap.OPT_REFERRALS, 0)  # type: ignore[attr-defined]
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)  # type: ignore[attr-defined]

        if bind_dn:
            conn.simple_bind_s(bind_dn, bind_password)
        else:
            conn.simple_bind_s("", "")

        current_app.logger.debug("LDAP bound successfully, searching...")

        fetch_attrs = [email_attr, fullname_attr, username_attr] + _EXTENDED_ATTRS

        results = conn.search_s(
            base_dn,
            ldap.SCOPE_SUBTREE,  # type: ignore[attr-defined]
            search_filter,
            fetch_attrs,
        )
        conn.unbind_s()

        current_app.logger.debug(f"LDAP search returned {len(results)} results")

        for dn, attrs in results:
            if dn is None:
                continue

            current_app.logger.debug(f"LDAP result: dn={dn}, attrs={attrs}")

            email = _get_attr(attrs, email_attr)
            fullname = _get_attr(attrs, fullname_attr) or ""
            sam = _get_attr(attrs, username_attr) or username

            if not email:
                current_app.logger.debug(f"LDAP result skipped: no email attribute ({email_attr})")
                continue

            return _build_ldap_user(domain, sam, email, fullname, attrs)

    except Exception as e:
        current_app.logger.error(f"LDAP lookup failed for {domain}\\{username}: {e}")

    return None


def lookup_by_email(email: str) -> LdapUser | None:
    """Look up a user by email across all configured LDAP domains."""
    if not is_ldap_enabled() or not is_ldap_available():
        return None

    import ldap
    import ldap.filter

    domains = current_app.config.get("LDAP_DOMAINS", [])

    for domain in domains:
        server = current_app.config.get(f"LDAP_{domain}_SERVER")
        base_dn = current_app.config.get(f"LDAP_{domain}_BASE_DN")
        bind_dn = current_app.config.get(f"LDAP_{domain}_BIND_DN", "")
        bind_password = current_app.config.get(f"LDAP_{domain}_BIND_PASSWORD", "")
        email_attr = current_app.config.get(f"LDAP_{domain}_EMAIL_ATTR", "mail")
        email_filter = current_app.config.get(
            f"LDAP_{domain}_EMAIL_FILTER",
            f"(&(objectClass=user)({email_attr}={{email}}))",
        )
        fullname_attr = current_app.config.get(f"LDAP_{domain}_FULLNAME_ATTR", "displayName")
        username_attr = current_app.config.get(f"LDAP_{domain}_USERNAME_ATTR", "sAMAccountName")

        if not server or not base_dn:
            continue

        search_filter = email_filter.replace("{email}", ldap.filter.escape_filter_chars(email))

        try:
            conn = ldap.initialize(server)
            conn.set_option(ldap.OPT_REFERRALS, 0)  # type: ignore[attr-defined]
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)  # type: ignore[attr-defined]

            if bind_dn:
                conn.simple_bind_s(bind_dn, bind_password)
            else:
                conn.simple_bind_s("", "")

            fetch_attrs = [email_attr, fullname_attr, username_attr] + _EXTENDED_ATTRS

            results = conn.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,  # type: ignore[attr-defined]
                search_filter,
                fetch_attrs,
            )
            conn.unbind_s()

            for dn, attrs in results:
                if dn is None:
                    continue

                fullname = _get_attr(attrs, fullname_attr) or ""
                sam = _get_attr(attrs, username_attr)

                if not sam:
                    continue

                return _build_ldap_user(domain, sam, email, fullname, attrs)

        except Exception as e:
            current_app.logger.error(f"LDAP email lookup failed in {domain}: {e}")

    return None


_EXTENDED_ATTRS = [
    "givenName",
    "mailNickname",
    "title",
    "department",
    "manager",
    "telephoneNumber",
    "mobile",
    "memberOf",
]


def _extract_cn(dn: str) -> str:
    """Extract the CN value from a distinguished name."""
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


def _get_attr(attrs: dict, name: str) -> str | None:
    """Extract a single-valued attribute from LDAP results."""
    values = attrs.get(name, [])
    if not values:
        return None
    val = values[0]
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _get_multi_attr(attrs: dict, name: str) -> list[str]:
    """Extract a multi-valued attribute from LDAP results."""
    values = attrs.get(name, [])
    result = []
    for val in values:
        if isinstance(val, bytes):
            result.append(val.decode("utf-8", errors="replace"))
        else:
            result.append(str(val))
    return result


def _build_ldap_user(domain: str, sam: str, email: str, fullname: str, attrs: dict) -> LdapUser:
    """Build an LdapUser from raw LDAP attributes."""
    manager_dn = _get_attr(attrs, "manager") or ""
    manager_cn = _extract_cn(manager_dn) if manager_dn else ""

    member_of = _get_multi_attr(attrs, "memberOf")
    group_cns = [_extract_cn(dn) for dn in member_of]

    return LdapUser(
        username=f"{domain}\\{sam}",
        email=email,
        fullname=fullname,
        given_name=_get_attr(attrs, "givenName") or "",
        mail_nickname=_get_attr(attrs, "mailNickname") or "",
        title=_get_attr(attrs, "title") or "",
        department=_get_attr(attrs, "department") or "",
        manager=manager_cn,
        telephone_number=_get_attr(attrs, "telephoneNumber") or "",
        mobile_number=_get_attr(attrs, "mobile") or "",
        groups=group_cns,
    )


def lookup_full_details(domain: str, username: str) -> LdapUser | None:
    """Fetch all extended attributes for a user. Reusable for refresh operations."""
    return lookup_by_username(domain, username)
