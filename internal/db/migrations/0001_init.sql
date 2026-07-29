-- ownership: which human owns which agent, once the two-sided !owner/!adopt handshake
-- (adoptbot, a later work package) confirms it.
CREATE TABLE ownership (
    agent_mxid TEXT PRIMARY KEY,
    owner_mxid TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- verified: humans who have completed whatever "verified" means for the adopt flow (out of
-- scope here — populated by a later work package).
CREATE TABLE verified (
    mxid TEXT PRIMARY KEY,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- pending_claims: backs the two-sided adopt handshake — one side's claim (agent's !owner or
-- human's !adopt) waits here for the other side to confirm it.
CREATE TABLE pending_claims (
    agent_mxid TEXT PRIMARY KEY,
    owner_mxid TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
