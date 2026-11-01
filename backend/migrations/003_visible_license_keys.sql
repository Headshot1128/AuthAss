ALTER TABLE licenses ADD COLUMN key_ciphertext TEXT;
INSERT INTO schema_migrations VALUES(3);
