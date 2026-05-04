CREATE TABLE policy_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL,
    tool_name   TEXT NOT NULL,
    allowed     INTEGER NOT NULL DEFAULT 1,  -- 1=allow, 0=deny
    created_at  INTEGER NOT NULL,
    UNIQUE(agent_id, tool_name)
);
CREATE INDEX idx_policy_agent ON policy_rules(agent_id);
