-- Personal API tokens (API tokens plan). Only the SHA-256 of a token is kept.
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    prefix       TEXT    NOT NULL,
    token_hash   TEXT    NOT NULL UNIQUE,
    read_only    INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER,
    last_used_ip TEXT,
    UNIQUE (user_id, name)
);
CREATE INDEX api_tokens_user ON api_tokens(user_id);
