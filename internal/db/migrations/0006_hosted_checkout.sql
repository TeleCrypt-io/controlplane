-- Hosted checkout lets Dodo collect the customer's real billing details. Keep a short-lived
-- reservation locally so repeated clicks cannot create parallel subscriptions before the first
-- subscription webhook binds a Dodo subscription id to the team.
ALTER TABLE teams
    ADD COLUMN checkout_session_id TEXT,
    ADD COLUMN checkout_started_at TIMESTAMPTZ;

CREATE UNIQUE INDEX teams_checkout_session_id_unique
    ON teams (checkout_session_id)
    WHERE checkout_session_id IS NOT NULL;
