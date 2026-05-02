CREATE TABLE access_tokens (
    token_hash  TEXT PRIMARY KEY,   -- SHA-256 hex of bearer token
    client_id   TEXT NOT NULL REFERENCES oauth_clients(client_id),
    agent_id    TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_access_tokens_expires ON access_tokens(expires_at);
