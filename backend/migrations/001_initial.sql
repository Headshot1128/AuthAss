CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
CREATE TABLE users(
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','revoked')),
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 subscription_until INTEGER NOT NULL DEFAULT 0, password_until INTEGER,
 created_at INTEGER NOT NULL
);
CREATE TABLE sessions(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), audience TEXT NOT NULL,
 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, hardware_hash TEXT
);
CREATE TABLE access_tokens(
 hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id), expires_at INTEGER NOT NULL
);
CREATE TABLE refresh_tokens(
 hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id), used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE permissions(
 user_id TEXT NOT NULL REFERENCES users(id), permission TEXT NOT NULL,
 PRIMARY KEY(user_id,permission)
);
CREATE TABLE licenses(
 id TEXT PRIMARY KEY, key_hash TEXT UNIQUE NOT NULL, expires_at INTEGER NOT NULL,
 permission TEXT NOT NULL, hardware_bound INTEGER NOT NULL DEFAULT 0,
 hardware_hash TEXT, user_id TEXT REFERENCES users(id), revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE variables(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, user_id TEXT REFERENCES users(id),
 value TEXT NOT NULL, permission TEXT NOT NULL
);
CREATE UNIQUE INDEX variables_scope ON variables(name,COALESCE(user_id,''));
CREATE TABLE files(
 id TEXT PRIMARY KEY, storage_name TEXT NOT NULL UNIQUE, permission TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, max_bytes INTEGER NOT NULL
);
CREATE TABLE audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, actor_id TEXT,
 event TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL
);
CREATE TABLE rate_limits(
 bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL
);
INSERT INTO schema_migrations VALUES(1);
