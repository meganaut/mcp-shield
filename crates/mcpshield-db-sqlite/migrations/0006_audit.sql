CREATE TABLE IF NOT EXISTS audit_events (
    id             TEXT    NOT NULL PRIMARY KEY,
    timestamp_ms   INTEGER NOT NULL,
    agent_id       TEXT    NOT NULL,
    operation_name TEXT    NOT NULL,
    outcome        TEXT    NOT NULL,
    latency_ms     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_agent_id  ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp_ms DESC);
