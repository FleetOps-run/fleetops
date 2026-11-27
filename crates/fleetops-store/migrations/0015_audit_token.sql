-- The API token a row was written through (API tokens are Enterprise;
-- the name outlives the token, so there is no foreign key).
ALTER TABLE audit_log ADD COLUMN token_id INTEGER;
ALTER TABLE audit_log ADD COLUMN token_name TEXT;
