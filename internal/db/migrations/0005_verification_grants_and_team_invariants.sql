-- `verified` predates billing and remains the manual/break-glass grant source. Do not migrate
-- rows out of it: historical rows do not contain trustworthy provenance.
--
-- Billing grants are separate, so a failed subscription or detached seat cannot revoke an
-- operator's manual grant. A grant is tied to the exact team/seat pair and follows the seat when
-- that pair is deleted.
ALTER TABLE seats
    ADD CONSTRAINT seats_team_id_mxid_key UNIQUE (team_id, mxid);

CREATE TABLE billing_verification_grants (
    mxid       TEXT PRIMARY KEY,
    team_id    UUID NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT billing_verification_grants_seat_fkey
        FOREIGN KEY (team_id, mxid) REFERENCES seats (team_id, mxid) ON DELETE CASCADE
);

-- A team is managed by exactly one Matrix account and a Dodo subscription is never shared.
-- The partial index intentionally still treats an empty string as a value: only SQL NULL means
-- "not yet bound to a subscription".
CREATE UNIQUE INDEX teams_admin_mxid_unique_idx ON teams (admin_mxid);
CREATE UNIQUE INDEX teams_dodo_subscription_id_unique_idx
    ON teams (dodo_subscription_id) WHERE dodo_subscription_id IS NOT NULL;

ALTER TABLE teams
    ADD CONSTRAINT teams_paid_seats_nonnegative CHECK (paid_seats >= 0),
    ADD CONSTRAINT teams_subscription_status_valid CHECK (
        subscription_status IN ('none', 'pending', 'active', 'on_hold', 'failed', 'cancelled', 'expired')
    );

-- 0004 created the reference without cascading deletion. Discover its generated name rather
-- than assuming a particular PostgreSQL naming convention, then recreate it with the intended
-- lifecycle. The migration runs inside the migrator transaction, so it cannot leave the table
-- with no foreign key if the replacement fails.
DO $$
DECLARE
    old_constraint TEXT;
BEGIN
    SELECT conname INTO old_constraint
    FROM pg_constraint
    WHERE conrelid = 'seats'::regclass
      AND confrelid = 'teams'::regclass
      AND contype = 'f'
    LIMIT 1;

    IF old_constraint IS NOT NULL THEN
        EXECUTE format('ALTER TABLE seats DROP CONSTRAINT %I', old_constraint);
    END IF;
END $$;

ALTER TABLE seats
    ADD CONSTRAINT seats_team_id_fkey
    FOREIGN KEY (team_id) REFERENCES teams (id) ON DELETE CASCADE;
