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

// ErrSeatCapacityReached and ErrCheckoutInProgress are safe business-condition
// sentinels for HTTP handlers. They deliberately do not expose database details.
var (
	ErrSeatCapacityReached       = errors.New("no paid seats available")
	ErrCheckoutInProgress        = errors.New("checkout already in progress")
	ErrSeatCountChangeInProgress = errors.New("seat count change already in progress")
	ErrLiveSubscription          = errors.New("subscription is already active")
	ErrStaleSubscription         = errors.New("stale subscription event")
)

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// BindBillingEnvironment permanently assigns this database to one explicit billing-provider
// environment and Matrix deployment. The singleton row prevents Dodo test and live state—or two
// Matrix deployments—from ever sharing a database merely because an operator changed env vars.
func (s *Store) BindBillingEnvironment(ctx context.Context, billingEnv, matrixDeployment string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO billing_environment_guard (singleton, billing_env, matrix_deployment_id)
		VALUES (TRUE, $1, $2)
		ON CONFLICT (singleton) DO NOTHING
	`, billingEnv, matrixDeployment); err != nil {
		return fmt.Errorf("bind billing environment: %w", err)
	}

	var boundEnv, boundDeployment string
	if err := s.pool.QueryRow(ctx, `
		SELECT billing_env, matrix_deployment_id
		FROM billing_environment_guard
		WHERE singleton = TRUE
	`).Scan(&boundEnv, &boundDeployment); err != nil {
		return fmt.Errorf("read billing environment binding: %w", err)
	}
	if boundEnv != billingEnv || boundDeployment != matrixDeployment {
		return fmt.Errorf(
			"billing database is bound to environment %q and deployment %q, not %q and %q",
			boundEnv, boundDeployment, billingEnv, matrixDeployment,
		)
	}
	return nil
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

const (
	janitorLockKeyPrefix       = "janitor-lock:"
	janitorLockIntentKeyPrefix = "janitor-lock-intent:"
)

// JanitorLockState returns exact confirmed MAS locked_at timestamps plus pre-call intents. MAS
// exposes no actor/reason for a lock, so timestamp identity prevents janitor from reversing an
// operator unlock/relock cycle. A durable intent closes the crash/ambiguous-response gap between
// deciding to lock and persisting MAS's successful response.
func (s *Store) JanitorLockState(ctx context.Context) (
	confirmed, pending map[string]time.Time,
	err error,
) {
	rows, err := s.pool.Query(ctx, `
		SELECT 'confirmed', substr(key, length($1) + 1), value
		FROM locker_state
		WHERE key LIKE $1 || '%'
		UNION ALL
		SELECT 'pending', substr(key, length($2) + 1), value
		FROM locker_state
		WHERE key LIKE $2 || '%'
	`, janitorLockKeyPrefix, janitorLockIntentKeyPrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("query janitor lock state: %w", err)
	}
	defer rows.Close()

	confirmed = make(map[string]time.Time)
	pending = make(map[string]time.Time)
	for rows.Next() {
		var kind, userID string
		var at time.Time
		if err := rows.Scan(&kind, &userID, &at); err != nil {
			return nil, nil, fmt.Errorf("scan janitor lock state: %w", err)
		}
		if kind == "confirmed" {
			confirmed[userID] = at
		} else {
			pending[userID] = at
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate janitor lock state: %w", err)
	}
	return confirmed, pending, nil
}

// BeginJanitorLock durably records intent before calling MAS. A later sweep can distinguish a
// committed-but-response-lost lock from a call that never changed MAS.
func (s *Store) BeginJanitorLock(ctx context.Context, userID string) (time.Time, error) {
	beganAt := time.Now().UTC()
	if err := s.SetLockerHighWaterMark(ctx, janitorLockIntentKeyPrefix+userID, beganAt); err != nil {
		return time.Time{}, err
	}
	return beganAt, nil
}

// ConfirmJanitorLock atomically stores MAS's exact locked_at timestamp and clears the pre-call
// intent. On failure the transaction leaves the intent intact for a later sweep to reconcile.
func (s *Store) ConfirmJanitorLock(ctx context.Context, userID string, lockedAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin janitor lock confirmation %s: %w", userID, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `
		INSERT INTO locker_state (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, janitorLockKeyPrefix+userID, lockedAt); err != nil {
		return fmt.Errorf("record confirmed janitor lock %s: %w", userID, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM locker_state WHERE key = $1`, janitorLockIntentKeyPrefix+userID); err != nil {
		return fmt.Errorf("clear janitor lock intent %s: %w", userID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit janitor lock confirmation %s: %w", userID, err)
	}
	return nil
}

// DeleteJanitorLock removes both confirmed provenance and any pending intent after an unlock,
// deactivation transfer, or when MAS is already unlocked. It intentionally does not mutate MAS.
func (s *Store) DeleteJanitorLock(ctx context.Context, userID string) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM locker_state WHERE key = $1 OR key = $2`,
		janitorLockKeyPrefix+userID,
		janitorLockIntentKeyPrefix+userID,
	); err != nil {
		return fmt.Errorf("delete janitor lock state %s: %w", userID, err)
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
	CheckoutAttemptID  *uuid.UUID
	PendingPaidSeats   *int
	SeatCountStartedAt *time.Time
	SeatCountAttemptID *uuid.UUID
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
	var checkoutAttemptID *uuid.UUID
	var pendingPaidSeats *int
	var seatCountStartedAt *time.Time
	var seatCountAttemptID *uuid.UUID
	err := row.Scan(
		&t.ID, &t.AdminMXID, &dodoCustomerID, &dodoSubID,
		&checkoutSessionID, &checkoutStartedAt, &checkoutAttemptID,
		&pendingPaidSeats, &seatCountStartedAt, &seatCountAttemptID,
		&t.SubscriptionStatus, &t.PaidSeats, &t.CreatedAt,
	)
	if err != nil {
		return Team{}, err
	}
	t.DodoCustomerID = dodoCustomerID
	t.DodoSubscriptionID = dodoSubID
	t.CheckoutSessionID = checkoutSessionID
	t.CheckoutStartedAt = checkoutStartedAt
	t.CheckoutAttemptID = checkoutAttemptID
	t.PendingPaidSeats = pendingPaidSeats
	t.SeatCountStartedAt = seatCountStartedAt
	t.SeatCountAttemptID = seatCountAttemptID
	return t, nil
}

const teamSelectCols = `
	id, admin_mxid, dodo_customer_id, dodo_subscription_id,
	checkout_session_id, checkout_started_at, checkout_attempt_id,
	pending_paid_seats, seat_count_change_started_at, seat_count_change_attempt_id,
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

// AttachSeat atomically checks capacity and attaches mxid.  A process-local mutex is
// insufficient because cashier can be replicated; the team row lock serializes every writer.
func (s *Store) AttachSeat(ctx context.Context, teamID uuid.UUID, mxid string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin attach seat: %w", err)
	}
	defer tx.Rollback(ctx)

	var paidSeats int
	var pendingPaidSeats *int
	if err := tx.QueryRow(ctx, `SELECT paid_seats, pending_paid_seats FROM teams WHERE id = $1 FOR UPDATE`, teamID).Scan(&paidSeats, &pendingPaidSeats); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("team not found: %w", err)
		}
		return fmt.Errorf("lock team for seat attach: %w", err)
	}
	var attached int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM seats WHERE team_id = $1`, teamID).Scan(&attached); err != nil {
		return fmt.Errorf("count seats for attach: %w", err)
	}
	effectiveCapacity := paidSeats
	if pendingPaidSeats != nil && *pendingPaidSeats < effectiveCapacity {
		effectiveCapacity = *pendingPaidSeats
	}
	if attached >= effectiveCapacity {
		return ErrSeatCapacityReached
	}
	if _, err := tx.Exec(ctx, `INSERT INTO seats (mxid, team_id) VALUES ($1, $2)`, mxid, teamID); err != nil {
		return fmt.Errorf("insert seat %s: %w", mxid, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit seat attach: %w", err)
	}
	return nil
}

// ReserveSeatCountChange atomically validates and records the target capacity before the
// provider call. AttachSeat applies the lower of paid_seats and this pending value, so a
// concurrent attachment cannot race a downgrade that Dodo has not acknowledged yet.
type SeatCountReservation struct {
	AttemptID uuid.UUID
	Attached  int
	Reused    bool
}

func (s *Store) ReserveSeatCountChange(ctx context.Context, teamID uuid.UUID, quantity int, now time.Time) (SeatCountReservation, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return SeatCountReservation{}, fmt.Errorf("begin seat count reservation: %w", err)
	}
	defer tx.Rollback(ctx)

	var status string
	var subscriptionID *string
	var pending *int
	var pendingAttempt *uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT subscription_status, dodo_subscription_id, pending_paid_seats, seat_count_change_attempt_id
		FROM teams WHERE id = $1 FOR UPDATE
	`, teamID).Scan(&status, &subscriptionID, &pending, &pendingAttempt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SeatCountReservation{}, fmt.Errorf("team not found: %w", err)
		}
		return SeatCountReservation{}, fmt.Errorf("lock team for seat count change: %w", err)
	}
	if (status != "active" && status != "on_hold") || subscriptionID == nil || *subscriptionID == "" {
		return SeatCountReservation{}, ErrLiveSubscription
	}
	if pending != nil {
		if *pending == quantity && pendingAttempt != nil {
			var attached int
			if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM seats WHERE team_id = $1`, teamID).Scan(&attached); err != nil {
				return SeatCountReservation{}, fmt.Errorf("count seats for repeated seat count change: %w", err)
			}
			return SeatCountReservation{AttemptID: *pendingAttempt, Attached: attached, Reused: true}, nil
		}
		return SeatCountReservation{}, ErrSeatCountChangeInProgress
	}

	var attached int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM seats WHERE team_id = $1`, teamID).Scan(&attached); err != nil {
		return SeatCountReservation{}, fmt.Errorf("count seats for seat count change: %w", err)
	}
	if attached > quantity {
		return SeatCountReservation{Attached: attached}, ErrSeatCapacityReached
	}
	attemptID := uuid.New()
	if _, err := tx.Exec(ctx, `
		UPDATE teams SET pending_paid_seats = $2, seat_count_change_started_at = $3,
			seat_count_change_attempt_id = $4
		WHERE id = $1
	`, teamID, quantity, now, attemptID); err != nil {
		return SeatCountReservation{}, fmt.Errorf("reserve seat count change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return SeatCountReservation{}, fmt.Errorf("commit seat count reservation: %w", err)
	}
	return SeatCountReservation{AttemptID: attemptID, Attached: attached}, nil
}

// ReleaseSeatCountChange removes only the reservation for the provider request that failed.
// The quantity predicate prevents an older worker from releasing a newer operation.
func (s *Store) ReleaseSeatCountChange(ctx context.Context, teamID uuid.UUID, attemptID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE teams SET pending_paid_seats = NULL, seat_count_change_started_at = NULL,
			seat_count_change_attempt_id = NULL
		WHERE id = $1 AND seat_count_change_attempt_id = $2
	`, teamID, attemptID)
	if err != nil {
		return fmt.Errorf("release seat count reservation: %w", err)
	}
	return nil
}

// InsertSeat is retained for migration/invariant tests and legacy callers. New cashier request
// paths must use AttachSeat, which is the capacity-safe operation.
// Deprecated: use AttachSeat.
func (s *Store) InsertSeat(ctx context.Context, teamID uuid.UUID, mxid string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO seats (mxid, team_id) VALUES ($1, $2)`, mxid, teamID)
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
			checkout_started_at = CASE WHEN $5::text IS NOT NULL THEN NULL ELSE checkout_started_at END,
			pending_paid_seats = NULL,
			seat_count_change_started_at = NULL,
			seat_count_change_attempt_id = NULL
		WHERE id = $1
	`, teamID, status, paidSeats, dodoCustomerID, dodoSubscriptionID)
	if err != nil {
		return fmt.Errorf("update team subscription: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE dodo_subscription_bindings
		SET status = $2, updated_at = now()
		WHERE team_id = $1 AND is_current
	`, teamID, status)
	if err != nil {
		return fmt.Errorf("update current subscription binding: %w", err)
	}
	return nil
}

// CheckoutReservation is the durable idempotency value for one hosted checkout attempt.
type CheckoutReservation struct{ AttemptID uuid.UUID }

// BeginCheckout reserves a checkout before the provider call. It supersedes a terminal
// subscription immediately, so delayed events for it cannot damage the replacement flow.
func (s *Store) BeginCheckout(ctx context.Context, teamID uuid.UUID, quantity int, now time.Time) (CheckoutReservation, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return CheckoutReservation{}, fmt.Errorf("begin checkout reservation: %w", err)
	}
	defer tx.Rollback(ctx)

	var status string
	var paidSeats int
	var startedAt *time.Time
	var existingAttemptID *uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT subscription_status, paid_seats, checkout_started_at, checkout_attempt_id
		FROM teams WHERE id = $1 FOR UPDATE
	`, teamID).Scan(&status, &paidSeats, &startedAt, &existingAttemptID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CheckoutReservation{}, fmt.Errorf("team not found: %w", err)
		}
		return CheckoutReservation{}, fmt.Errorf("lock team for checkout: %w", err)
	}
	if status == "active" || status == "on_hold" {
		return CheckoutReservation{}, ErrLiveSubscription
	}
	if status == "pending" && startedAt != nil && now.Sub(*startedAt) < 24*time.Hour {
		if existingAttemptID != nil && paidSeats == quantity {
			return CheckoutReservation{AttemptID: *existingAttemptID}, nil
		}
		return CheckoutReservation{}, ErrCheckoutInProgress
	}

	attemptID := uuid.New()
	if _, err := tx.Exec(ctx, `
		UPDATE dodo_subscription_bindings SET is_current = FALSE, updated_at = now()
		WHERE team_id = $1 AND is_current
	`, teamID); err != nil {
		return CheckoutReservation{}, fmt.Errorf("supersede terminal subscription: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE teams SET
			subscription_status = 'pending', paid_seats = $2,
			dodo_subscription_id = NULL,
			checkout_session_id = NULL, checkout_started_at = $3,
			checkout_attempt_id = $4,
			checkout_previous_status = $5, checkout_previous_paid_seats = $6
		WHERE id = $1
	`, teamID, quantity, now, attemptID, status, paidSeats); err != nil {
		return CheckoutReservation{}, fmt.Errorf("reserve checkout: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return CheckoutReservation{}, fmt.Errorf("commit checkout reservation: %w", err)
	}
	return CheckoutReservation{AttemptID: attemptID}, nil
}

// CompleteCheckoutReservation records the provider session only if it belongs to the current
// attempt. A stale worker can therefore never overwrite a newer checkout.
func (s *Store) CompleteCheckoutReservation(ctx context.Context, teamID uuid.UUID, attemptID uuid.UUID, sessionID string) error {
	command, err := s.pool.Exec(ctx, `
		UPDATE teams SET checkout_session_id = $3
		WHERE id = $1 AND checkout_attempt_id = $2
	`, teamID, attemptID, sessionID)
	if err != nil {
		return fmt.Errorf("record hosted checkout: %w", err)
	}
	if command.RowsAffected() != 1 {
		return errors.New("checkout reservation no longer current")
	}
	return nil
}

// ReleaseCheckoutReservation restores the terminal/no-subscription state after a provider
// failure. It is conditional on the attempt id, so it cannot release a newer checkout.
func (s *Store) ReleaseCheckoutReservation(ctx context.Context, teamID uuid.UUID, attemptID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE teams SET
			subscription_status = COALESCE(checkout_previous_status, 'none'),
			paid_seats = COALESCE(checkout_previous_paid_seats, 0),
			checkout_session_id = NULL, checkout_started_at = NULL,
			checkout_attempt_id = NULL,
			checkout_previous_status = NULL, checkout_previous_paid_seats = NULL
		WHERE id = $1 AND checkout_attempt_id = $2
	`, teamID, attemptID)
	if err != nil {
		return fmt.Errorf("release checkout reservation: %w", err)
	}
	return nil
}

// SubscriptionBinding records whether a provider subscription may still mutate its team.
type SubscriptionBinding struct {
	TeamID    uuid.UUID
	IsCurrent bool
}

func (s *Store) GetSubscriptionBinding(ctx context.Context, subscriptionID string) (SubscriptionBinding, bool, error) {
	var b SubscriptionBinding
	err := s.pool.QueryRow(ctx, `
		SELECT team_id, is_current FROM dodo_subscription_bindings WHERE subscription_id = $1
	`, subscriptionID).Scan(&b.TeamID, &b.IsCurrent)
	if errors.Is(err, pgx.ErrNoRows) {
		return SubscriptionBinding{}, false, nil
	}
	if err != nil {
		return SubscriptionBinding{}, false, fmt.Errorf("get subscription binding: %w", err)
	}
	return b, true, nil
}

// BindCurrentSubscription atomically accepts the first event for a pending checkout, or updates
// an already-current provider subscription. Superseded ids are permanently rejected.
func (s *Store) BindCurrentSubscription(ctx context.Context, teamID uuid.UUID, subscriptionID, customerID, status string, paidSeats int) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin subscription bind: %w", err)
	}
	defer tx.Rollback(ctx)

	// Always lock the team before its binding. BeginCheckout uses the same order; keeping a
	// single lock order prevents a checkout/webhook deadlock under concurrent delivery.
	var teamStatus string
	var attemptID *uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT subscription_status, checkout_attempt_id
		FROM teams WHERE id = $1 FOR UPDATE
	`, teamID).Scan(&teamStatus, &attemptID); err != nil {
		return fmt.Errorf("lock team for subscription bind: %w", err)
	}

	var boundTeamID uuid.UUID
	var current bool
	var previousStatus string
	err = tx.QueryRow(ctx, `SELECT team_id, is_current, status FROM dodo_subscription_bindings WHERE subscription_id = $1 FOR UPDATE`, subscriptionID).Scan(&boundTeamID, &current, &previousStatus)
	if err == nil {
		if boundTeamID != teamID || !current {
			return ErrStaleSubscription
		}
		if isTerminalSubscriptionStatus(previousStatus) && !isTerminalSubscriptionStatus(status) {
			return ErrStaleSubscription
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lock subscription binding: %w", err)
	} else {
		if teamStatus != "pending" || attemptID == nil {
			return ErrStaleSubscription
		}
		if _, err := tx.Exec(ctx, `UPDATE dodo_subscription_bindings SET is_current = FALSE, updated_at = now() WHERE team_id = $1 AND is_current`, teamID); err != nil {
			return fmt.Errorf("supersede subscription binding: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dodo_subscription_bindings (subscription_id, team_id, is_current, status) VALUES ($1, $2, TRUE, $3)`, subscriptionID, teamID, status); err != nil {
			return fmt.Errorf("insert subscription binding: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE dodo_subscription_bindings SET status = $2, updated_at = now() WHERE subscription_id = $1
	`, subscriptionID, status); err != nil {
		return fmt.Errorf("update subscription binding: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE teams SET
			subscription_status = $2, paid_seats = $3,
			dodo_customer_id = CASE WHEN $4 <> '' THEN $4 ELSE dodo_customer_id END,
			dodo_subscription_id = $5,
			checkout_session_id = NULL, checkout_started_at = NULL,
			checkout_attempt_id = NULL,
			checkout_previous_status = NULL, checkout_previous_paid_seats = NULL,
			pending_paid_seats = NULL, seat_count_change_started_at = NULL,
			seat_count_change_attempt_id = NULL
		WHERE id = $1
	`, teamID, status, paidSeats, customerID, subscriptionID); err != nil {
		return fmt.Errorf("update team subscription binding: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit subscription bind: %w", err)
	}
	return nil
}

func isTerminalSubscriptionStatus(status string) bool {
	switch status {
	case "failed", "cancelled", "expired":
		return true
	default:
		return false
	}
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
