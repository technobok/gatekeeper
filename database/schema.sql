-- Gatekeeper Authentication Service Schema

CREATE TABLE IF NOT EXISTS db_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO db_metadata VALUES ('schema_version', '1');

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
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_email ON user(email);

CREATE TABLE IF NOT EXISTS grp (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
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

-- Default data
INSERT OR IGNORE INTO app_setting VALUES ('app_salt', hex(randomblob(16)), 'Global session invalidation salt');
INSERT OR IGNORE INTO grp VALUES ('admin', 'Administrators', datetime('now'), datetime('now'));
INSERT OR IGNORE INTO grp VALUES ('standard', 'Standard users', datetime('now'), datetime('now'));
