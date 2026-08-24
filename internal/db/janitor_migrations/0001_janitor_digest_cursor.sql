-- Janitor-owned digest delivery cursor. This is intentionally separate from the retained,
-- published public-schema locker_state migration.
CREATE TABLE janitor.janitor_digest_cursor (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton = TRUE),
    created_at TIMESTAMPTZ NOT NULL,
    email_id TEXT NOT NULL
);
