-- A checkout attempt is reserved before calling Dodo.  That reservation is durable across
-- processes, so a double-click cannot create two subscriptions.  The previous state lets a
-- failed remote checkout be released without accidentally changing an existing terminal state.
ALTER TABLE teams
    ADD COLUMN checkout_attempt_id UUID,
    ADD COLUMN checkout_previous_status TEXT,
    ADD COLUMN checkout_previous_paid_seats INT,
    ADD COLUMN pending_paid_seats INT CHECK (pending_paid_seats IS NULL OR pending_paid_seats >= 1),
    ADD COLUMN seat_count_change_started_at TIMESTAMPTZ,
    ADD COLUMN seat_count_change_attempt_id UUID;

CREATE UNIQUE INDEX teams_checkout_attempt_id_unique
    ON teams (checkout_attempt_id)
    WHERE checkout_attempt_id IS NOT NULL;

CREATE UNIQUE INDEX teams_seat_count_change_attempt_id_unique
    ON teams (seat_count_change_attempt_id)
    WHERE seat_count_change_attempt_id IS NOT NULL;

-- Keep every Dodo subscription id that has ever belonged to a team.  A metadata-only webhook
-- cannot distinguish a replacement checkout from a delayed event for an older subscription;
-- this table makes that distinction explicit.
CREATE TABLE dodo_subscription_bindings (
    subscription_id TEXT PRIMARY KEY,
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    is_current      BOOLEAN NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX dodo_subscription_bindings_one_current_per_team
    ON dodo_subscription_bindings (team_id)
    WHERE is_current;

-- Existing deployments used teams.dodo_subscription_id as the current binding.  Preserve that
-- knowledge before new checkouts begin superseding terminal subscriptions.
INSERT INTO dodo_subscription_bindings (subscription_id, team_id, is_current, status)
SELECT dodo_subscription_id, id, TRUE, subscription_status
FROM teams
WHERE dodo_subscription_id IS NOT NULL;
