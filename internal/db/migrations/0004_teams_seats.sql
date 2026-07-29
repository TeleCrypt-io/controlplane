-- teams: one paying entity. admin_mxid is the human who created it via the Plan-tab page.
CREATE TABLE teams (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_mxid           TEXT NOT NULL,
    dodo_customer_id     TEXT,
    dodo_subscription_id TEXT,
    subscription_status  TEXT NOT NULL DEFAULT 'none',  -- none|pending|active|on_hold|failed
    paid_seats           INT NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- seats: which mxids are attached to which team. mxid can be a bot or a human account — no
-- distinction is made anywhere in this schema or the code that reads it.
CREATE TABLE seats (
    mxid       TEXT PRIMARY KEY,
    team_id    UUID NOT NULL REFERENCES teams(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
