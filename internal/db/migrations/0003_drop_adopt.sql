-- Drops the retired two-sided ownership handshake tables. Team billing attaches a seat directly,
-- so no pending-claim handshake is needed. The `verified` table (0001_init.sql) is unaffected and
-- reused as-is by the planned `cashier` component.
DROP TABLE pending_claims;
DROP TABLE ownership;
