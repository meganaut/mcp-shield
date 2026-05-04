CREATE TABLE setup_state (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
-- Insert initial row so the wizard knows setup is not complete
INSERT INTO setup_state (key, value) VALUES ('setup_complete', '0');
