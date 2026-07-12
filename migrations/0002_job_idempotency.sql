ALTER TABLE jobs ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX jobs_type_idempotency ON jobs(type,idempotency_key) WHERE idempotency_key<>'';
