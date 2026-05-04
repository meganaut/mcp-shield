CREATE TABLE oauth_clients (
    client_id            TEXT PRIMARY KEY,
    agent_id             TEXT NOT NULL UNIQUE,  -- UUID, stable internal identifier
    client_secret_hash   TEXT NOT NULL,
    client_name          TEXT NOT NULL,
    redirect_uris        TEXT NOT NULL,          -- JSON array of strings
    created_at           INTEGER NOT NULL
);
