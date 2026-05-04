CREATE TABLE IF NOT EXISTS vault_tokens (
    id              TEXT    NOT NULL PRIMARY KEY,
    integration_id  TEXT    NOT NULL UNIQUE,
    nonce           BLOB    NOT NULL,
    ciphertext      BLOB    NOT NULL,
    expires_at      INTEGER,
    created_at      INTEGER NOT NULL,
    FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE
);
