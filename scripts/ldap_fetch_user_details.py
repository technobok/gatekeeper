#!/usr/bin/env python3
"""Fetch user details and photos from AD/LDAP for all database users.

Connects to the configured LDAP domains and attempts to retrieve:
  - givenName: first name
  - mailNickname: Exchange alias (often a natural short name)
  - title: job title
  - department: department
  - physicalDeliveryOfficeName: office location
  - manager: distinguished name of their manager
  - telephoneNumber: office phone
  - mobile: mobile phone
  - userAccountControl: account status flags
  - memberOf: AD group memberships
  - thumbnailPhoto: small user photo (typically from AD)
  - jpegPhoto: larger user photo (standard LDAP attribute)

Images are saved to the current working directory using a sanitised version
of the username as the filename.

Usage:
    python scripts/ldap_fetch_user_details.py
"""

import re
import sys

# Text attributes to fetch and display
TEXT_ATTRS = [
    "givenName",
    "mailNickname",
    "title",
    "department",
    "physicalDeliveryOfficeName",
    "manager",
    "telephoneNumber",
    "mobile",
    "userAccountControl",
]

# Multi-valued text attribute
MULTI_ATTRS = [
    "memberOf",
]

# Binary photo attributes
PHOTO_ATTRS = [
    ("thumbnailPhoto", "thumb"),
    ("jpegPhoto", "photo"),
]

ALL_ATTR_NAMES = (
    TEXT_ATTRS
    + MULTI_ATTRS
    + [name for name, _ in PHOTO_ATTRS]
)


def sanitise_filename(username: str) -> str:
    """Convert a username to a safe filename (no slashes, backslashes, etc.)."""
    return re.sub(r'[\\/:*?"<>|]', "_", username)


def decode_value(val: bytes | str) -> str:
    """Decode a single LDAP attribute value to a string."""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def fetch_ldap_attrs(app, domain: str, bare_username: str) -> dict | None:
    """Query LDAP for user details and photos.

    Returns a dict of raw attribute values on success, or None on failure.
    """
    try:
        import ldap
        import ldap.filter
    except ImportError:
        print("ERROR: python-ldap is not installed.", file=sys.stderr)
        sys.exit(1)

    server = app.config.get(f"LDAP_{domain}_SERVER")
    base_dn = app.config.get(f"LDAP_{domain}_BASE_DN")
    bind_dn = app.config.get(f"LDAP_{domain}_BIND_DN", "")
    bind_password = app.config.get(f"LDAP_{domain}_BIND_PASSWORD", "")
    user_filter = app.config.get(
        f"LDAP_{domain}_USER_FILTER",
        "(&(objectClass=user)(sAMAccountName={username}))",
    )

    if not server or not base_dn:
        return None

    search_filter = user_filter.replace(
        "{username}", ldap.filter.escape_filter_chars(bare_username)
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
            base_dn, ldap.SCOPE_SUBTREE, search_filter, ALL_ATTR_NAMES
        )
        conn.unbind_s()

        for dn, attrs in results:
            if dn is None:
                continue
            return attrs

    except Exception as exc:
        print(f"  LDAP error for {domain}\\{bare_username}: {exc}")

    return None


def main() -> None:
    from gatekeeper import create_app

    app = create_app()

    with app.app_context():
        from gatekeeper.models.user import User

        if not app.config.get("LDAP_ENABLED"):
            print("LDAP is not enabled in configuration. Nothing to do.")
            sys.exit(0)

        domains = app.config.get("LDAP_DOMAINS", [])
        if not domains:
            print("No LDAP domains configured. Nothing to do.")
            sys.exit(0)

        print(f"LDAP domains: {', '.join(domains)}")

        users = User.get_all(limit=100_000)
        print(f"Total users in database: {len(users)}\n")

        counts: dict[str, int] = {name: 0 for name in ALL_ATTR_NAMES}
        skipped = 0

        for user in users:
            username = user.username

            # Determine domain(s) and bare username to search
            if "\\" in username:
                parts = username.split("\\", 1)
                search_pairs = [(parts[0].upper(), parts[1])]
            else:
                # Not a domain user -- try all configured domains
                search_pairs = [(d, username) for d in domains]

            attrs = None
            for domain, bare in search_pairs:
                if domain not in domains:
                    continue
                attrs = fetch_ldap_attrs(app, domain, bare)
                if attrs is not None:
                    break

            if attrs is None:
                print(f"  {username}: not found in LDAP (skipped)")
                skipped += 1
                continue

            # -- single-valued text attributes --
            for attr_name in TEXT_ATTRS:
                raw = attrs.get(attr_name, [])
                if raw:
                    print(f"  {username}: {attr_name} = {decode_value(raw[0])}")
                    counts[attr_name] += 1
                else:
                    print(f"  {username}: {attr_name} not set")

            # -- multi-valued text attributes --
            for attr_name in MULTI_ATTRS:
                raw = attrs.get(attr_name, [])
                if raw:
                    values = [decode_value(v) for v in raw]
                    print(f"  {username}: {attr_name} ({len(values)} entries)")
                    for v in values:
                        print(f"    - {v}")
                    counts[attr_name] += 1
                else:
                    print(f"  {username}: {attr_name} not set")

            # -- photo attributes --
            safe_name = sanitise_filename(username)
            for attr_name, suffix in PHOTO_ATTRS:
                raw = attrs.get(attr_name, [])
                if raw:
                    photo_data = raw[0]
                    if isinstance(photo_data, bytes) and len(photo_data) > 0:
                        path = f"{safe_name}_{suffix}.jpg"
                        with open(path, "wb") as f:
                            f.write(photo_data)
                        print(f"  {username}: {attr_name} saved -> {path} ({len(photo_data)} bytes)")
                        counts[attr_name] += 1
                    else:
                        print(f"  {username}: {attr_name} empty")
                else:
                    print(f"  {username}: {attr_name} not set")

        print(f"\n--- Summary ---")
        print(f"Users processed : {len(users)}")
        print(f"Not in LDAP     : {skipped}")
        max_label = max(len(name) for name in ALL_ATTR_NAMES)
        for name in ALL_ATTR_NAMES:
            print(f"{name:<{max_label}} : {counts[name]}")


if __name__ == "__main__":
    main()
