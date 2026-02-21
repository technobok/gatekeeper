#!/usr/bin/env python3
"""Fetch givenName and photos (thumbnailPhoto, jpegPhoto) from AD/LDAP for all database users.

Connects to the configured LDAP domains and attempts to retrieve:
  - givenName: an informal/first name for the user
  - thumbnailPhoto: small user photo (typically from AD)
  - jpegPhoto: larger user photo (standard LDAP attribute)

Images are saved to the current working directory using a sanitised version
of the username as the filename.

Usage:
    python scripts/ldap_fetch_user_details.py
"""

import re
import sys


def sanitise_filename(username: str) -> str:
    """Convert a username to a safe filename (no slashes, backslashes, etc.)."""
    return re.sub(r'[\\/:*?"<>|]', "_", username)


def fetch_ldap_attrs(app, domain: str, bare_username: str) -> dict | None:
    """Query LDAP for givenName, thumbnailPhoto, and jpegPhoto.

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

    attrs_to_fetch = ["givenName", "thumbnailPhoto", "jpegPhoto"]

    try:
        conn = ldap.initialize(server)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)

        if bind_dn:
            conn.simple_bind_s(bind_dn, bind_password)
        else:
            conn.simple_bind_s("", "")

        results = conn.search_s(
            base_dn, ldap.SCOPE_SUBTREE, search_filter, attrs_to_fetch
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

        found_given = 0
        found_thumb = 0
        found_jpeg = 0
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

            # -- givenName --
            given_raw = attrs.get("givenName", [])
            if given_raw:
                val = given_raw[0]
                given_name = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
                print(f"  {username}: givenName = {given_name}")
                found_given += 1
            else:
                given_name = None
                print(f"  {username}: givenName not set")

            safe_name = sanitise_filename(username)

            # -- thumbnailPhoto --
            thumb_raw = attrs.get("thumbnailPhoto", [])
            if thumb_raw:
                photo_data = thumb_raw[0]
                if isinstance(photo_data, bytes) and len(photo_data) > 0:
                    path = f"{safe_name}_thumb.jpg"
                    with open(path, "wb") as f:
                        f.write(photo_data)
                    print(f"  {username}: thumbnailPhoto saved -> {path} ({len(photo_data)} bytes)")
                    found_thumb += 1
                else:
                    print(f"  {username}: thumbnailPhoto empty")
            else:
                print(f"  {username}: thumbnailPhoto not set")

            # -- jpegPhoto --
            jpeg_raw = attrs.get("jpegPhoto", [])
            if jpeg_raw:
                photo_data = jpeg_raw[0]
                if isinstance(photo_data, bytes) and len(photo_data) > 0:
                    path = f"{safe_name}_photo.jpg"
                    with open(path, "wb") as f:
                        f.write(photo_data)
                    print(f"  {username}: jpegPhoto saved -> {path} ({len(photo_data)} bytes)")
                    found_jpeg += 1
                else:
                    print(f"  {username}: jpegPhoto empty")
            else:
                print(f"  {username}: jpegPhoto not set")

        print(f"\n--- Summary ---")
        print(f"Users processed : {len(users)}")
        print(f"Not in LDAP     : {skipped}")
        print(f"givenName found : {found_given}")
        print(f"thumbnailPhoto  : {found_thumb}")
        print(f"jpegPhoto       : {found_jpeg}")


if __name__ == "__main__":
    main()
