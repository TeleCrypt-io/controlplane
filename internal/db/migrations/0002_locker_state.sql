-- locker_state: janitor's persisted high-water marks (currently just
-- 'digest_high_water', the created_at cutoff of the last successfully emailed owner digest) so a
-- crashed run never loses or duplicates a whole reporting window. Advance only after a confirmed
-- send (or logged-in-lieu-of-send in degraded mode) — duplicates at the boundary are acceptable,
-- losses are not.
CREATE TABLE locker_state (
    key TEXT PRIMARY KEY,
    value TIMESTAMPTZ NOT NULL
);
