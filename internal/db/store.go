// Package db stores Janitor's manual verification and maintenance state.
package db

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
)

type Store struct { pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// BindBillingEnvironment verifies the guard written exclusively by private Cashier.
func (s *Store) BindBillingEnvironment(ctx context.Context, billingEnv, matrixDeployment string) error {
    var boundEnv, boundDeployment string
    err := s.pool.QueryRow(ctx, `SELECT billing_env, matrix_deployment_id FROM cashier.billing_environment_guard WHERE singleton = TRUE`).Scan(&boundEnv, &boundDeployment)
    if errors.Is(err, pgx.ErrNoRows) { return fmt.Errorf("private cashier has not bound the billing environment") }
    if err != nil { return fmt.Errorf("read private cashier billing environment binding: %w", err) }
    if boundEnv != billingEnv || boundDeployment != matrixDeployment {
        return fmt.Errorf("billing database is bound to environment %q and deployment %q, not %q and %q", boundEnv, boundDeployment, billingEnv, matrixDeployment)
    }
    return nil
}

// VerifiedMXIDs combines manual grants with Cashier-owned billing grants without allowing
// Janitor to modify either source.
func (s *Store) VerifiedMXIDs(ctx context.Context) (map[string]bool, error) {
    rows, err := s.pool.Query(ctx, `SELECT mxid FROM verified UNION SELECT mxid FROM cashier.billing_verification_grants`)
    if err != nil { return nil, fmt.Errorf("query verified: %w", err) }
    defer rows.Close()
    set := make(map[string]bool)
    for rows.Next() {
        var mxid string
        if err := rows.Scan(&mxid); err != nil { return nil, fmt.Errorf("scan verified row: %w", err) }
        set[mxid] = true
    }
    if err := rows.Err(); err != nil { return nil, fmt.Errorf("iterate verified rows: %w", err) }
    return set, nil
}

func (s *Store) IsVerified(ctx context.Context, mxid string) (bool, error) {
    var exists bool
    err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM verified WHERE mxid = $1 UNION ALL SELECT 1 FROM cashier.billing_verification_grants WHERE mxid = $1)`, mxid).Scan(&exists)
    if err != nil { return false, fmt.Errorf("query verified %s: %w", mxid, err) }
    return exists, nil
}

func (s *Store) LockerHighWaterMark(ctx context.Context, key string) (time.Time, bool, error) {
    var value time.Time
    err := s.pool.QueryRow(ctx, `SELECT value FROM locker_state WHERE key = $1`, key).Scan(&value)
    if errors.Is(err, pgx.ErrNoRows) { return time.Time{}, false, nil }
    if err != nil { return time.Time{}, false, fmt.Errorf("query locker_state %s: %w", key, err) }
    return value, true, nil
}

func (s *Store) SetLockerHighWaterMark(ctx context.Context, key string, value time.Time) error {
    _, err := s.pool.Exec(ctx, `INSERT INTO locker_state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value)
    if err != nil { return fmt.Errorf("upsert locker_state %s: %w", key, err) }
    return nil
}

const (
    janitorLockKeyPrefix = "janitor-lock:"
    janitorLockIntentKeyPrefix = "janitor-lock-intent:"
)

func (s *Store) JanitorLockState(ctx context.Context) (confirmed, pending map[string]time.Time, err error) {
    rows, err := s.pool.Query(ctx, `
        SELECT 'confirmed', substr(key, length($1) + 1), value FROM locker_state WHERE key LIKE $1 || '%'
        UNION ALL
        SELECT 'pending', substr(key, length($2) + 1), value FROM locker_state WHERE key LIKE $2 || '%'`, janitorLockKeyPrefix, janitorLockIntentKeyPrefix)
    if err != nil { return nil, nil, fmt.Errorf("query janitor lock state: %w", err) }
    defer rows.Close()
    confirmed, pending = make(map[string]time.Time), make(map[string]time.Time)
    for rows.Next() {
        var kind, userID string; var at time.Time
        if err := rows.Scan(&kind, &userID, &at); err != nil { return nil, nil, fmt.Errorf("scan janitor lock state: %w", err) }
        if kind == "confirmed" { confirmed[userID] = at } else { pending[userID] = at }
    }
    if err := rows.Err(); err != nil { return nil, nil, fmt.Errorf("iterate janitor lock state: %w", err) }
    return confirmed, pending, nil
}

func (s *Store) BeginJanitorLock(ctx context.Context, userID string) (time.Time, error) {
    beganAt := time.Now().UTC()
    if err := s.SetLockerHighWaterMark(ctx, janitorLockIntentKeyPrefix+userID, beganAt); err != nil { return time.Time{}, err }
    return beganAt, nil
}

func (s *Store) ConfirmJanitorLock(ctx context.Context, userID string, lockedAt time.Time) error {
    tx, err := s.pool.Begin(ctx)
    if err != nil { return fmt.Errorf("begin janitor lock confirmation %s: %w", userID, err) }
    defer tx.Rollback(ctx)
    if _, err := tx.Exec(ctx, `INSERT INTO locker_state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, janitorLockKeyPrefix+userID, lockedAt); err != nil { return fmt.Errorf("record confirmed janitor lock %s: %w", userID, err) }
    if _, err := tx.Exec(ctx, `DELETE FROM locker_state WHERE key = $1`, janitorLockIntentKeyPrefix+userID); err != nil { return fmt.Errorf("clear janitor lock intent %s: %w", userID, err) }
    if err := tx.Commit(ctx); err != nil { return fmt.Errorf("commit janitor lock confirmation %s: %w", userID, err) }
    return nil
}

func (s *Store) DeleteJanitorLock(ctx context.Context, userID string) error {
    _, err := s.pool.Exec(ctx, `DELETE FROM locker_state WHERE key = $1 OR key = $2`, janitorLockKeyPrefix+userID, janitorLockIntentKeyPrefix+userID)
    if err != nil { return fmt.Errorf("delete janitor lock state %s: %w", userID, err) }
    return nil
}
