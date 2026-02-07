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

# Create a blank database (writes to instance/gatekeeper.sqlite3)
make init-db

# Set a mail sender (needed for magic links)
make config-set KEY=mail.mail_sender VAL=auth@example.com

# Create an initial admin user
.venv/bin/gatekeeper-admin create-admin --username admin --email admin@example.com

# Start the development server (127.0.0.1:5100, debug mode)
make rundev
```

Open http://127.0.0.1:5100 in a browser. You'll see the login page — enter the admin email and a magic link will be sent (provided you have an outbox service configured, see below).

### Database location

By default the database is created at `instance/gatekeeper.sqlite3` relative to the project root. Set the `GATEKEEPER_DB` environment variable to override:

```bash
export GATEKEEPER_DB=/data/gatekeeper.sqlite3
```

The resolution order is:

1. `GATEKEEPER_DB` environment variable (if set)
2. Flask `DATABASE_PATH` config (when running inside the web server)
3. `instance/gatekeeper.sqlite3` relative to the source tree (fallback)

All CLI commands (`gatekeeper-admin`, `make config-*`, `make init-db`) and the web server use the same resolution logic — set `GATEKEEPER_DB` once and everything finds the database.

### Run with Docker

```bash
docker compose build
docker compose up -d
```

The container exposes port 5100 and persists data at `./instance/gatekeeper.sqlite3` via a volume mount. Inside the container, `GATEKEEPER_DB` is set to `/data/gatekeeper.sqlite3`.

### Production

```bash
# Gunicorn, 2 workers, bound to 0.0.0.0:5100
make run
```

## Integrating with Python applications

The client library is included in the `gatekeeper` package and can be used directly by any Python application. Install from GitHub:

```bash
pip install git+ssh://git@github.com/technobok/gatekeeper.git
```

### Local mode (direct database access)

Best when the consuming app runs on the same host or can mount the database file. The client reads the signing key directly from the database — no extra configuration needed.

```python
from gatekeeper import GatekeeperClient

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
from gatekeeper import GatekeeperClient

gk = GatekeeperClient(
    server_url="https://auth.internal.example.com",
    api_key="gk_...",
)
gk.init_app(app)
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

## Configuration reference

All settings are stored in the SQLite database (`app_setting` table) and managed via `make config-set` or `gatekeeper-admin config set`. Use `make config-list` to see current values.

### General settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server.host` | string | `0.0.0.0` | Bind address for production server |
| `server.port` | int | `5100` | Port for production server |
| `server.dev_host` | string | `127.0.0.1` | Bind address for dev server |
| `server.dev_port` | int | `5100` | Port for dev server |
| `server.debug` | bool | `false` | Enable Flask debug mode |
| `mail.mail_sender` | string | | Email sender address (required for magic links) |
| `outbox.db_path` | string | | Path to outbox SQLite database (local delivery) |
| `outbox.url` | string | | Outbox HTTP API base URL (remote delivery) |
| `outbox.api_key` | string | | Outbox API key |
| `auth.magic_link_expiry_seconds` | int | `3600` | Magic link token lifetime |
| `auth.admin_emails` | string list | | Comma-separated emails to auto-provision as admins |
| `proxy.x_forwarded_for` | int | `0` | Trust X-Forwarded-For (hop count) |
| `proxy.x_forwarded_proto` | int | `0` | Trust X-Forwarded-Proto (hop count) |
| `proxy.x_forwarded_host` | int | `0` | Trust X-Forwarded-Host (hop count) |
| `proxy.x_forwarded_prefix` | int | `0` | Trust X-Forwarded-Prefix (hop count) |

### LDAP configuration

Enable LDAP and list the domain names:

```bash
make config-set KEY=ldap.enabled VAL=true
make config-set KEY=ldap.domains VAL="CORP,APAC"
```

Then configure each domain with per-domain keys using the pattern `ldap.<DOMAIN>.<field>`:

```bash
make config-set KEY=ldap.CORP.server         VAL="ldap://dc.corp.example.com"
make config-set KEY=ldap.CORP.base_dn        VAL="DC=corp,DC=example,DC=com"
make config-set KEY=ldap.CORP.bind_dn        VAL="CN=svc-gatekeeper,OU=Service Accounts,DC=corp,DC=example,DC=com"
make config-set KEY=ldap.CORP.bind_password   VAL="secret"
```

The full set of per-domain fields:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ldap.<DOMAIN>.server` | string | | LDAP server URI (e.g. `ldap://dc.corp.example.com`) |
| `ldap.<DOMAIN>.base_dn` | string | | Search base DN |
| `ldap.<DOMAIN>.bind_dn` | string | | Bind DN (empty for anonymous bind) |
| `ldap.<DOMAIN>.bind_password` | string | | Bind password |
| `ldap.<DOMAIN>.user_filter` | string | `(&(objectClass=user)(sAMAccountName={username}))` | LDAP filter for username lookup |
| `ldap.<DOMAIN>.email_attr` | string | `mail` | LDAP attribute for email |
| `ldap.<DOMAIN>.email_filter` | string | auto | LDAP filter for email lookup (auto-built from `email_attr` if empty) |
| `ldap.<DOMAIN>.fullname_attr` | string | `displayName` | LDAP attribute for full name |
| `ldap.<DOMAIN>.username_attr` | string | `sAMAccountName` | LDAP attribute for username |

Users found via LDAP are auto-provisioned into Gatekeeper and added to the `standard` group. Login identifiers can be `domain\username`, `email`, or bare `username` (searched across all domains).

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
