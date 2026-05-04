CREATE TABLE auth_codes (
    code            TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES oauth_clients(client_id),
    redirect_uri    TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_auth_codes_expires ON auth_codes(expires_at);
