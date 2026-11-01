ALTER TABLE users ADD COLUMN console_only INTEGER NOT NULL DEFAULT 0 CHECK(console_only IN (0,1));
UPDATE users SET console_only=1 WHERE role='admin';
UPDATE sessions SET revoked=1 WHERE audience='client' AND user_id IN (SELECT id FROM users WHERE console_only=1);
INSERT INTO schema_migrations VALUES(2);
