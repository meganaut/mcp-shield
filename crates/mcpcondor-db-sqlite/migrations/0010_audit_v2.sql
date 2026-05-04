-- M4: extended audit log — correlation ID, integration slug, deny reason, error detail, client id, DLP

ALTER TABLE audit_events ADD COLUMN integration_slug TEXT;
ALTER TABLE audit_events ADD COLUMN deny_reason      TEXT;
ALTER TABLE audit_events ADD COLUMN error_message    TEXT;
ALTER TABLE audit_events ADD COLUMN client_id        TEXT;
ALTER TABLE audit_events ADD COLUMN dlp_detections   TEXT;  -- JSON array, NULL when empty

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts   ON audit_events(agent_id, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_audit_slug        ON audit_events(integration_slug);
