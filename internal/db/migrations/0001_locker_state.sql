-- Janitor's durable maintenance state. Keys record the digest high-water mark and lock
-- provenance; Cashier owns all billing and entitlement state in the private cashier schema.
CREATE TABLE locker_state (
    key TEXT PRIMARY KEY,
    value TIMESTAMPTZ NOT NULL
);
