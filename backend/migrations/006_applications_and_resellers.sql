CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reseller_profiles (
    user_id TEXT PRIMARY KEY,
    max_days INTEGER NOT NULL DEFAULT 30
);

INSERT OR IGNORE INTO applications(id, name, status, created_at)
VALUES('00000000-0000-4000-8000-000000000001', 'Default application', 'active', 0);
