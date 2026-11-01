ALTER TABLE users ADD COLUMN web_approved INTEGER NOT NULL DEFAULT 0 CHECK(web_approved IN (0,1));
INSERT INTO schema_migrations VALUES(4);
