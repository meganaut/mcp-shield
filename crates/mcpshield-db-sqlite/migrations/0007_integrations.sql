CREATE TABLE IF NOT EXISTS integrations (
    id                TEXT    NOT NULL PRIMARY KEY,
    slug              TEXT    NOT NULL UNIQUE,
    name              TEXT    NOT NULL,
    mcp_url           TEXT    NOT NULL,
    oauth_auth_url    TEXT,
    oauth_token_url   TEXT,
    oauth_client_id   TEXT,
    oauth_scopes      TEXT,
    connected         INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);
