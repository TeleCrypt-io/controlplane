// Package db holds the control-plane schema (see migrations/) and the shared Store type that
// later work packages (janitor, cashier) build their queries on top of. redpill itself holds no
// database connection at all — Store exists here only so the schema and its migration runner have
// a home in this repo ahead of those binaries.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// VerifiedMXIDs returns the full effective verification set. The legacy verified table is the
// owner-controlled/manual source of truth; billing_verification_grants contains the separate,
// cashier-controlled source. Keeping those sources distinct means a billing revocation can never
// erase a manual break-glass grant. Loaded as one set rather than queried per-candidate: janitor's
// sweep walks the entire MAS user list, so one query here is cheaper than one round-trip per
// candidate account.
func (s *Store) VerifiedMXIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT mxid FROM verified
		UNION
		SELECT mxid FROM billing_verification_grants
	`)
	if err != nil {
		return nil, fmt.Errorf("query verified: %w", err)
	}
	defer rows.Close()

	set := make(map[string]bool)
	for rows.Next() {
		var mxid string
		if err := rows.Scan(&mxid); err != nil {
			return nil, fmt.Errorf("scan verified row: %w", err)
		}
		set[mxid] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate verified rows: %w", err)
	}
	return set, nil
}

// LockerHighWaterMark returns the current value of locker_state's row for key, and found=false if
// no sweep has ever successfully advanced it (e.g. the very first run).
func (s *Store) LockerHighWaterMark(ctx context.Context, key string) (value time.Time, found bool, err error) {
	err = s.pool.QueryRow(ctx, `SELECT value FROM locker_state WHERE key = $1`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, fmt.Errorf("query locker_state %s: %w", key, err)
	}
	return value, true, nil
}

// SetLockerHighWaterMark upserts key -> value in locker_state. A single INSERT .. ON CONFLICT
// statement is already atomic in Postgres, so janitor's read-then-maybe-advance sequence
// can't land the mark in a torn state — a crash leaves it at either the old value or the new one,
// never a partial write. This is deliberately not wrapped together with the email send in one
// transaction: holding a DB transaction open across an outbound SMTP call would block the
// connection pool on network I/O for no benefit, and a sent email can't be rolled back anyway.
func (s *Store) SetLockerHighWaterMark(ctx context.Context, key string, value time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO locker_state (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, key, value)
	if err != nil {
		return fmt.Errorf("upsert locker_state %s: %w", key, err)
	}
	return nil
}

// IsVerified reports whether mxid has any verification grant. It is suitable for read-only
// callers; cashier must use the source-specific methods below so it only mutates billing grants.
func (s *Store) IsVerified(ctx context.Context, mxid string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM verified WHERE mxid = $1
			UNION ALL
			SELECT 1 FROM billing_verification_grants WHERE mxid = $1
		)
	`, mxid).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query verified %s: %w", mxid, err)
	}
	return exists, nil
}

// HasManualVerificationGrant reports whether mxid has the legacy/manual break-glass grant.
// Existing verified rows intentionally remain manual when migration 0005 is applied: historical
// data cannot reliably identify which rows were created by an operator versus an older cashier.
func (s *Store) HasManualVerificationGrant(ctx context.Context, mxid string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM verified WHERE mxid = $1)`, mxid).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query manual verification grant %s: %w", mxid, err)
	}
	return exists, nil
}

// HasBillingVerificationGrant reports whether cashier currently grants mxid access.
func (s *Store) HasBillingVerificationGrant(ctx context.Context, mxid string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_verification_grants WHERE mxid = $1)`, mxid).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query billing verification grant %s: %w", mxid, err)
	}
	return exists, nil
}

// InsertBillingVerificationGrant records a cashier-managed grant for an attached seat. The
// composite foreign key in migration 0005 proves that mxid still belongs to teamID; a stale
// reconciliation therefore cannot attach a grant to a removed or different team's seat.
func (s *Store) InsertBillingVerificationGrant(ctx context.Context, teamID uuid.UUID, mxid string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO billing_verification_grants (team_id, mxid) VALUES ($1, $2)
		ON CONFLICT (mxid) DO NOTHING
	`, teamID, mxid)
	if err != nil {
		return fmt.Errorf("insert billing verification grant %s: %w", mxid, err)
	}
	return nil
}

// DeleteBillingVerificationGrant removes only cashier's source of access. It deliberately does
// not touch verified, which belongs to the manual break-glass path.
func (s *Store) DeleteBillingVerificationGrant(ctx context.Context, mxid string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM billing_verification_grants WHERE mxid = $1`, mxid)
	if err != nil {
		return fmt.Errorf("delete billing verification grant %s: %w", mxid, err)
	}
	return nil
}

// InsertVerified adds a manual/break-glass verification grant if not already present. It remains
// for compatibility with the owner tool; cashier must not call it.
func (s *Store) InsertVerified(ctx context.Context, mxid string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO verified (mxid) VALUES ($1) ON CONFLICT (mxid) DO NOTHING
	`, mxid)
	if err != nil {
		return fmt.Errorf("insert verified %s: %w", mxid, err)
	}
	return nil
}

// DeleteVerified removes a manual/break-glass grant. It does not remove any billing grant.
func (s *Store) DeleteVerified(ctx context.Context, mxid string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM verified WHERE mxid = $1`, mxid)
	if err != nil {
		return fmt.Errorf("delete verified %s: %w", mxid, err)
	}
	return nil
}

// Team is one paying entity managed via the Plan tab.
type Team struct {
	ID                 uuid.UUID
	AdminMXID          string
	DodoCustomerID     *string
	DodoSubscriptionID *string
	CheckoutSessionID  *string
	CheckoutStartedAt  *time.Time
	SubscriptionStatus string
	PaidSeats          int
	CreatedAt          time.Time
}

// Seat is one Matrix account attached to a team.
type Seat struct {
	MXID      string
	TeamID    uuid.UUID
	CreatedAt time.Time
}

func scanTeam(row pgx.Row) (Team, error) {
	var t Team
	var dodoCustomerID, dodoSubID, checkoutSessionID *string
	var checkoutStartedAt *time.Time
	err := row.Scan(
		&t.ID, &t.AdminMXID, &dodoCustomerID, &dodoSubID,
		&checkoutSessionID, &checkoutStartedAt,
		&t.SubscriptionStatus, &t.PaidSeats, &t.CreatedAt,
	)
	if err != nil {
		return Team{}, err
	}
	t.DodoCustomerID = dodoCustomerID
	t.DodoSubscriptionID = dodoSubID
	t.CheckoutSessionID = checkoutSessionID
	t.CheckoutStartedAt = checkoutStartedAt
	return t, nil
}

const teamSelectCols = `
	id, admin_mxid, dodo_customer_id, dodo_subscription_id,
	checkout_session_id, checkout_started_at,
	subscription_status, paid_seats, created_at
`

// CreateTeam inserts a new team with admin_mxid set to the Plan-tab caller.
func (s *Store) CreateTeam(ctx context.Context, adminMXID string) (Team, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO teams (admin_mxid) VALUES ($1)
		RETURNING `+teamSelectCols, adminMXID)
	t, err := scanTeam(row)
	if err != nil {
		return Team{}, fmt.Errorf("create team: %w", err)
	}
	return t, nil
}

// GetTeamByID loads a team by primary key.
func (s *Store) GetTeamByID(ctx context.Context, teamID uuid.UUID) (Team, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+teamSelectCols+` FROM teams WHERE id = $1`, teamID)
	t, err := scanTeam(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Team{}, fmt.Errorf("team not found: %w", err)
		}
		return Team{}, fmt.Errorf("get team by id: %w", err)
	}
	return t, nil
}

// GetTeamByAdminMXID loads the team whose admin_mxid matches the session caller.
func (s *Store) GetTeamByAdminMXID(ctx context.Context, adminMXID string) (Team, bool, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+teamSelectCols+` FROM teams WHERE admin_mxid = $1`, adminMXID)
	t, err := scanTeam(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Team{}, false, nil
		}
		return Team{}, false, fmt.Errorf("get team by admin mxid: %w", err)
	}
	return t, true, nil
}

// GetTeamByDodoSubscriptionID loads a team by its Dodo subscription id.
func (s *Store) GetTeamByDodoSubscriptionID(ctx context.Context, subscriptionID string) (Team, bool, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+teamSelectCols+` FROM teams WHERE dodo_subscription_id = $1`, subscriptionID)
	t, err := scanTeam(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Team{}, false, nil
		}
		return Team{}, false, fmt.Errorf("get team by subscription id: %w", err)
	}
	return t, true, nil
}

// InsertSeat attaches mxid to teamID.
func (s *Store) InsertSeat(ctx context.Context, teamID uuid.UUID, mxid string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO seats (mxid, team_id) VALUES ($1, $2)
	`, mxid, teamID)
	if err != nil {
		return fmt.Errorf("insert seat %s: %w", mxid, err)
	}
	return nil
}

// DeleteSeat removes mxid from seats.
func (s *Store) DeleteSeat(ctx context.Context, mxid string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM seats WHERE mxid = $1`, mxid)
	if err != nil {
		return fmt.Errorf("delete seat %s: %w", mxid, err)
	}
	return nil
}

// CountSeatsForTeam returns how many seats are attached to teamID.
func (s *Store) CountSeatsForTeam(ctx context.Context, teamID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM seats WHERE team_id = $1`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count seats: %w", err)
	}
	return n, nil
}

// ListSeatsForTeam returns seats ordered by created_at ascending (oldest first).
func (s *Store) ListSeatsForTeam(ctx context.Context, teamID uuid.UUID) ([]Seat, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT mxid, team_id, created_at FROM seats
		WHERE team_id = $1 ORDER BY created_at ASC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list seats: %w", err)
	}
	defer rows.Close()

	var seats []Seat
	for rows.Next() {
		var seat Seat
		if err := rows.Scan(&seat.MXID, &seat.TeamID, &seat.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan seat: %w", err)
		}
		seats = append(seats, seat)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate seats: %w", err)
	}
	return seats, nil
}

// UpdateTeamSubscription updates billing fields after a Dodo webhook or checkout.
func (s *Store) UpdateTeamSubscription(ctx context.Context, teamID uuid.UUID, status string, paidSeats int, dodoCustomerID, dodoSubscriptionID *string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE teams SET
			subscription_status = $2,
			paid_seats = $3,
			dodo_customer_id = COALESCE($4, dodo_customer_id),
			dodo_subscription_id = COALESCE($5, dodo_subscription_id),
			checkout_session_id = CASE WHEN $5::text IS NOT NULL THEN NULL ELSE checkout_session_id END,
			checkout_started_at = CASE WHEN $5::text IS NOT NULL THEN NULL ELSE checkout_started_at END
		WHERE id = $1
	`, teamID, status, paidSeats, dodoCustomerID, dodoSubscriptionID)
	if err != nil {
		return fmt.Errorf("update team subscription: %w", err)
	}
	return nil
}

// RecordHostedCheckout reserves one in-flight hosted checkout for a team.
func (s *Store) RecordHostedCheckout(ctx context.Context, teamID uuid.UUID, sessionID string, quantity int, startedAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE teams SET
			subscription_status = 'pending',
			paid_seats = $3,
			checkout_session_id = $2,
			checkout_started_at = $4
		WHERE id = $1
	`, teamID, sessionID, quantity, startedAt)
	if err != nil {
		return fmt.Errorf("record hosted checkout: %w", err)
	}
	return nil
}

// IsSeatMXID reports whether mxid appears in the seats table (any team).
func (s *Store) IsSeatMXID(ctx context.Context, mxid string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM seats WHERE mxid = $1)`, mxid).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query seat mxid %s: %w", mxid, err)
	}
	return exists, nil
}

// MarkWebhookProcessed records a processed Dodo webhook id (dedup for retries).
func (s *Store) MarkWebhookProcessed(ctx context.Context, webhookID string) error {
	return s.SetLockerHighWaterMark(ctx, "webhook:"+webhookID, time.Now().UTC())
}

// IsWebhookProcessed reports whether webhookID was already handled.
func (s *Store) IsWebhookProcessed(ctx context.Context, webhookID string) (bool, error) {
	_, found, err := s.LockerHighWaterMark(ctx, "webhook:"+webhookID)
	if err != nil {
		return false, err
	}
	return found, nil
}
