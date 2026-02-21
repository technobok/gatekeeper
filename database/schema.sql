-- Gatekeeper Authentication Service Schema

CREATE TABLE IF NOT EXISTS db_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO db_metadata VALUES ('schema_version', '3');

CREATE TABLE IF NOT EXISTS app_setting (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS user (
    username TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    fullname TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    login_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ldap_domain TEXT NOT NULL DEFAULT '',
    given_name TEXT NOT NULL DEFAULT '',
    mail_nickname TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    manager TEXT NOT NULL DEFAULT '',
    telephone_number TEXT NOT NULL DEFAULT '',
    mobile_number TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_user_email ON user(email);

CREATE TABLE IF NOT EXISTS grp (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'gatekeeper'
);

CREATE TABLE IF NOT EXISTS group_user (
    group_name TEXT NOT NULL REFERENCES grp(name) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES user(username) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (group_name, username)
);

CREATE TABLE IF NOT EXISTS api_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS user_property (
    username TEXT NOT NULL REFERENCES user(username) ON DELETE CASCADE,
    app      TEXT NOT NULL,
    key      TEXT NOT NULL,
    value    TEXT,
    PRIMARY KEY (username, app, key)
);

CREATE INDEX IF NOT EXISTS idx_user_property_username ON user_property(username);

-- Default data
INSERT OR IGNORE INTO app_setting VALUES ('app_salt', hex(randomblob(16)), 'Global session invalidation salt');
INSERT OR IGNORE INTO grp VALUES ('admin', 'Administrators', datetime('now'), datetime('now'), 'gatekeeper');
INSERT OR IGNORE INTO grp VALUES ('standard', 'Standard users', datetime('now'), datetime('now'), 'gatekeeper');
