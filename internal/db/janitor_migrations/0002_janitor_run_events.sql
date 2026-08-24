-- Append-only bounded audit events for one-shot Janitor runs. No account identifiers, email
-- addresses, provider errors, access tokens, or free-form messages are retained here.
CREATE TABLE janitor.run_events (
    event_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('started', 'finished')),
    status TEXT NOT NULL CHECK (status IN ('started', 'succeeded', 'failed')),
    outcome TEXT NOT NULL CHECK (outcome IN ('pending', 'dry_run', 'success', 'operational_failure')),
    reason TEXT NOT NULL CHECK (reason IN ('pending', 'would_disable', 'disabled', 'no_eligible_accounts', 'database', 'mas', 'entitlement_view', 'notification', 'audit', 'cancelled', 'lock', 'lock_readback')),
    server_name TEXT NOT NULL,
    billing_environment TEXT NOT NULL CHECK (billing_environment IN ('test', 'live')),
    dry_run BOOLEAN NOT NULL,
    considered BIGINT NOT NULL CHECK (considered >= 0),
    skipped BIGINT NOT NULL CHECK (skipped >= 0),
    locked_or_would_lock BIGINT NOT NULL CHECK (locked_or_would_lock >= 0),
    failures BIGINT NOT NULL CHECK (failures >= 0),
    notification_status TEXT NOT NULL CHECK (notification_status IN ('not_attempted', 'succeeded', 'failed')),
    labels TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[] CHECK (
        cardinality(labels) <= 16
        AND labels <@ ARRAY[
            'database', 'entitlement_view', 'mas_users', 'mas_emails', 'candidate_recheck',
            'lock', 'lock_readback', 'notification', 'audit_started', 'audit_finished', 'cancelled'
        ]::TEXT[]
    ),
    CONSTRAINT run_events_state_check CHECK (
        (event_kind = 'started' AND status = 'started' AND outcome = 'pending' AND reason = 'pending' AND notification_status = 'not_attempted')
        OR (event_kind = 'finished' AND status = 'succeeded' AND outcome IN ('dry_run', 'success') AND reason IN ('would_disable', 'disabled', 'no_eligible_accounts'))
        OR (event_kind = 'finished' AND status = 'failed' AND outcome = 'operational_failure' AND reason IN ('database', 'mas', 'entitlement_view', 'notification', 'audit', 'cancelled', 'lock', 'lock_readback'))
    )
);
