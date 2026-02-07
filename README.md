# Gatekeeper

A shared authentication service providing passwordless magic-link authentication, LDAP/Active Directory integration, API key management, and role-based access control — all backed by a self-contained SQLite database.

Gatekeeper sits at the centre of a fleet of internal tools, providing a single place to manage users, groups, and permissions. Any application can authenticate users through the Gatekeeper web interface and API. Python applications can also embed the client library directly for tighter integration.

## Quickstart

### Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) package manager

### Install and run locally

```bash
# Clone and install dependencies
cd gatekeeper
make sync

# Create a blank database
make init-db

# Set a mail sender (needed for magic links)
make config-set KEY=mail.mail_sender VAL=auth@example.com

# Create an initial admin user
.venv/bin/gatekeeper-admin create-admin --username admin --email admin@example.com

# Start the development server (127.0.0.1:5100, debug mode)
make rundev
```

Open http://127.0.0.1:5100 in a browser. You'll see the login page — enter the admin email and a magic link will be sent (provided you have an outbox service configured, see below).

### Run with Docker

```bash
docker compose build
docker compose up -d
```

The container exposes port 5100 and persists data at `./instance/gatekeeper.sqlite3` via a volume mount.

### Production

```bash
# Gunicorn, 2 workers, bound to 0.0.0.0:5100
make run
```

## Integrating with Python applications

The client library can be embedded directly into a Python application for tighter integration. Install it alongside your app:

```bash
pip install -e /path/to/gatekeeper   # or publish to a private index
```

### Local mode (direct database access)

Best when the consuming app runs on the same host or can mount the database file. The client reads the signing key directly from the database — no extra configuration needed.

```python
from gatekeeper_client import GatekeeperClient

gk = GatekeeperClient(db_path="/path/to/gatekeeper.sqlite3")
gk.init_app(app, cookie_name="gk_session")

@app.route("/dashboard")
@gk.login_required
def dashboard():
    user = g.user          # populated by before_request hook
    return f"Hello {user.fullname}"

@app.route("/admin")
@gk.group_required("admin")
def admin_panel():
    ...
```

### HTTP mode (remote API calls)

Use when the consuming app runs on a different host. Requires an API key — generate one from the admin console under API Keys.

```python
gk = GatekeeperClient(
    server_url="https://auth.internal.example.com",
    api_key="gk_...",
)
gk.init_app(app)
```

The client library has optional dependency groups — install only what you need:

```bash
pip install gatekeeper-client[local]   # apsw for direct DB access
pip install gatekeeper-client[http]    # httpx for remote calls
pip install gatekeeper-client[flask]   # Flask integration helpers
pip install gatekeeper-client[all]     # everything
```

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                  Gatekeeper Web Server                     │
│                                                           │
│  Blueprints    ─ auth          Login/logout, magic links  │
│                ─ api           JSON REST API (v1)         │
│                ─ admin_users   User CRUD (HTMX)          │
│                ─ admin_groups  Group CRUD (HTMX)         │
│                ─ admin_api_keys  API key management       │
│                ─ admin_system  Dashboard, config, audit   │
│                ─ admin_sql     Ad-hoc SQL query console   │
│                                                           │
│  Services      ─ token_service   Signed token lifecycle  │
│                ─ ldap_service    AD/LDAP user resolution  │
│                ─ email_service   Outbox-backed delivery   │
│                ─ export_service  XLSX report generation   │
│                                                           │
│  Models        ─ User, Group, ApiKey, UserProperty,      │
│                  AppSetting, AuditLog                     │
│                                                           │
│  Database      ─ SQLite (APSW), WAL mode, schema v2     │
└───────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│                 Gatekeeper Client Library                  │
│                                                           │
│  GatekeeperClient  ─ authenticate()  verify cookie token │
│                    ─ send_magic_link()                    │
│                    ─ User/group/property CRUD             │
│                    ─ init_app() + decorators for Flask    │
│                                                           │
│  Backends          ─ LocalBackend   (direct SQLite)      │
│                    ─ HttpBackend    (remote HTTP API)     │
└───────────────────────────────────────────────────────────┘
```

### Design decisions

**SQLite with APSW.** The entire state lives in a single file. No database server to install, back up, or upgrade. APSW gives WAL-mode concurrency, foreign key enforcement, and a cursor API that fits naturally with Python. For an internal auth service handling hundreds (not millions) of users this is the right trade-off: operational simplicity over horizontal scale.

**Passwordless magic links.** Passwords are the weakest link in most internal tools — people reuse them, forget them, and they need salting/hashing infrastructure. Magic links eliminate all of that. A signed, time-limited token is emailed to the user; clicking it logs them in. Sessions are invalidated by rotating per-user or global salts.

**Token signing with itsdangerous.** Auth tokens embed the username, a per-user `login_salt`, and a global `app_salt`. Rotating the user salt invalidates that user's sessions; rotating the app salt invalidates everyone's. No session store needed — tokens are self-contained and verified cryptographically.

**HTMX for the admin UI.** The admin dashboard uses server-rendered HTML with HTMX for dynamic updates. This avoids the complexity of a JavaScript SPA while still delivering a responsive interface. Partial HTML fragments are returned for in-place updates, keeping the server authoritative over all rendering.

**Dual-mode client library.** Applications on the same host can read the SQLite database directly for fast, zero-network-hop authentication. Applications on remote hosts call the HTTP API. Both modes expose the same `GatekeeperClient` interface, so application code doesn't change when the deployment topology does.

**Outbox-based email.** Rather than talking to an SMTP server directly, Gatekeeper queues messages through an outbox service (either by writing to its SQLite database or calling its HTTP API). This decouples email delivery from the auth flow and lets the outbox handle retries, rate limiting, and delivery tracking.

**Config stored in the database.** All settings (LDAP servers, mail sender, proxy config, admin emails) live in the `app_setting` table rather than in environment variables or config files. This makes settings inspectable and changeable at runtime via the CLI or admin UI, and avoids the drift that comes from managing INI files across environments. An `import` command is provided for initial bulk setup.

**Audit logging.** Every administrative action (user created, group membership changed, API key generated, salt rotated) is recorded in the `audit_log` table with a timestamp, actor, action type, and target. This provides an immutable trail for compliance and debugging.

## Makefile reference

| Target | Description |
|---|---|
| `make sync` | Install/sync dependencies with uv |
| `make init-db` | Create a blank database |
| `make import-users FILE=...` | Bulk import users from CSV (username, email, fullname) |
| `make bootstrap-key` | Generate an API key (mainly for bootstrapping Outbox integration where the two services are interdependent) |
| `make run` | Start production server (gunicorn, 0.0.0.0:5100) |
| `make rundev` | Start development server (Flask debug mode) |
| `make config-list` | Show all configuration settings |
| `make config-set KEY=... VAL=...` | Set a configuration value |
| `make config-import FILE=...` | Import settings from an INI file |
| `make check` | Run ruff (format + lint) and ty (type check) |
| `make clean` | Remove bytecode and the database file |

## CLI commands

The `gatekeeper-admin` CLI provides the same operations outside of Make:

```
gatekeeper-admin init-db              # Initialize the database schema
gatekeeper-admin create-admin         # Create an admin user interactively
gatekeeper-admin import-users FILE    # Bulk import from CSV
gatekeeper-admin generate-api-key     # Generate a new API key
gatekeeper-admin config list          # Show settings
gatekeeper-admin config set KEY VAL   # Set a setting
gatekeeper-admin config import FILE   # Import from INI
gatekeeper-admin ensure-admins        # Ensure auth.admin_emails accounts exist
```

## Roadmap

### Done

- [x] Passwordless magic-link authentication flow
- [x] User and group CRUD with RBAC (admin/standard groups)
- [x] API key authentication for service-to-service calls
- [x] HTMX-powered admin dashboard (users, groups, API keys, audit log)
- [x] LDAP/Active Directory integration with auto-provisioning
- [x] Client library with local (SQLite) and HTTP backends
- [x] Flask integration decorators (`@login_required`, `@group_required`)
- [x] Outbox-based email delivery (local DB and HTTP modes)
- [x] Configuration stored in SQLite with CLI management
- [x] Audit logging of all administrative actions
- [x] XLSX export for users, groups, API keys, and audit log
- [x] Ad-hoc SQL query console in admin UI
- [x] User properties (per-app, per-user key-value metadata)
- [x] Case-insensitive username handling
- [x] CSV bulk user import
- [x] Dark/light mode toggle in admin UI
- [x] Automatic schema migration (v1 to v2)
- [x] Per-user and global session invalidation via salt rotation
- [x] Reverse proxy support (ProxyFix configuration)
- [x] Docker and docker-compose deployment

### Planned

- [ ] Test suite (pytest — unit, integration, and blueprint-level tests)
- [ ] Token refresh / sliding session expiry
- [ ] Rate limiting on magic-link requests
- [ ] Multi-tenant support (scoped users/groups per application)
- [ ] Email template customisation (HTML templates for magic links)
- [ ] Backup and restore CLI commands

## Future directions

**WebAuthn / passkey support.** Magic links are convenient but still depend on email delivery. Adding passkey registration and authentication would give users a faster, phishing-resistant alternative while keeping the passwordless philosophy.

**OAuth2 / OIDC provider.** Gatekeeper currently issues its own signed tokens. Implementing an OpenID Connect provider would let third-party tools (Grafana, GitLab, wiki software) delegate authentication to Gatekeeper without needing the client library.

**Session management UI.** Currently there is no way for users or admins to see active sessions. A session ledger — showing device, IP, and last-active time — would make salt rotation less of a blunt instrument and give users visibility into their own activity.

**Webhook notifications.** Firing webhooks on events like user creation, group changes, or login would let downstream systems react in real time (e.g. provisioning accounts in other services, sending Slack alerts).

**Read replicas for the client library.** For deployments with many consuming apps, the local backend could be extended to read from a periodically-synced copy of the database rather than the live file, reducing lock contention.

**Admin impersonation.** An "act as user" feature for admins would simplify debugging permission issues in consuming applications without needing to send magic links or modify group memberships.
