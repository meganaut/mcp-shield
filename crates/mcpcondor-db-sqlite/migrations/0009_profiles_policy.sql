-- M4: profiles, profile rules, global rules, agent overrides
-- Replaces policy_rules with agent_overrides; adds profile system

-- Profiles
CREATE TABLE profiles (
    id          TEXT    NOT NULL PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

-- Built-in default profile (seeded once; never deleted)
INSERT INTO profiles (id, name, description, is_default, created_at)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'Default profile for new agents', 1, strftime('%s', 'now') * 1000);

-- Per-profile static tool rules
CREATE TABLE profile_rules (
    profile_id  TEXT    NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    tool_name   TEXT    NOT NULL,
    allowed     INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (profile_id, tool_name)
);

-- Fleet-wide global rules (layer 1 = hard deny, layer 5 = global allow)
CREATE TABLE global_rules (
    tool_name   TEXT    NOT NULL PRIMARY KEY,
    allowed     INTEGER NOT NULL,  -- 0 = hard deny, 1 = global allow
    created_at  INTEGER NOT NULL
);

-- Agent overrides: per-agent exceptions (supersedes policy_rules)
CREATE TABLE agent_overrides (
    agent_id    TEXT    NOT NULL,
    tool_name   TEXT    NOT NULL,
    allowed     INTEGER NOT NULL,
    kind        TEXT    NOT NULL DEFAULT 'static',  -- 'static' | 'until' | 'uses'
    expires_at  INTEGER,           -- non-null when kind = 'until'
    remaining   INTEGER,           -- non-null when kind = 'uses'
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (agent_id, tool_name)
);
CREATE INDEX idx_agent_overrides_agent ON agent_overrides(agent_id);

-- Migrate existing policy_rules rows into agent_overrides
INSERT INTO agent_overrides (agent_id, tool_name, allowed, kind, created_at)
SELECT agent_id, tool_name, allowed, 'static', created_at FROM policy_rules;

-- Drop old table
DROP TABLE policy_rules;

-- oauth_clients gains profile_id (NULL = Default profile)
ALTER TABLE oauth_clients ADD COLUMN profile_id TEXT REFERENCES profiles(id);

-- integrations gains default_stance (0 = deny all, 1 = allow all)
ALTER TABLE integrations ADD COLUMN default_stance INTEGER NOT NULL DEFAULT 0;
