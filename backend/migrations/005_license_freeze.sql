ALTER TABLE licenses ADD COLUMN frozen_at INTEGER;
ALTER TABLE users ADD COLUMN frozen_at INTEGER;
INSERT INTO schema_migrations(version) VALUES(5);
