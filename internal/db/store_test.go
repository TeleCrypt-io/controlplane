// TestStore requires a real Postgres reachable at TEST_DATABASE_URL — skipped automatically if the
// env var isn't set. See migrate_test.go's header for how to stand up a throwaway Postgres.
package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS billing_environment_guard, dodo_subscription_bindings, billing_verification_grants, seats, teams, ownership, verified, pending_claims, locker_state, schema_migrations`,
	); err != nil {
		t.Fatalf("drop existing tables: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	return NewStore(pool), pool
}

func TestVerifiedMXIDs(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	set, err := store.VerifiedMXIDs(ctx)
	if err != nil {
		t.Fatalf("VerifiedMXIDs (empty): %v", err)
	}
	if len(set) != 0 {
		t.Fatalf("expected empty set, got %v", set)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO verified (mxid) VALUES ($1), ($2)`, "@alice:telecrypt.io", "@bob:telecrypt.io",
	); err != nil {
		t.Fatalf("insert verified rows: %v", err)
	}

	set, err = store.VerifiedMXIDs(ctx)
	if err != nil {
		t.Fatalf("VerifiedMXIDs: %v", err)
	}
	if !set["@alice:telecrypt.io"] || !set["@bob:telecrypt.io"] {
		t.Fatalf("expected both mxids present, got %v", set)
	}
	if len(set) != 2 {
		t.Fatalf("expected exactly 2 entries, got %d", len(set))
	}
}

func TestBindBillingEnvironment(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	if err := store.BindBillingEnvironment(ctx, "test", "production"); err != nil {
		t.Fatalf("first BindBillingEnvironment: %v", err)
	}
	if err := store.BindBillingEnvironment(ctx, "test", "production"); err != nil {
		t.Fatalf("idempotent BindBillingEnvironment: %v", err)
	}
	if err := store.BindBillingEnvironment(ctx, "production", "production"); err == nil {
		t.Fatal("environment mismatch unexpectedly accepted")
	}
	if err := store.BindBillingEnvironment(ctx, "test", "another-test"); err == nil {
		t.Fatal("deployment mismatch unexpectedly accepted")
	}
}

func TestLockerHighWaterMark(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	_, found, err := store.LockerHighWaterMark(ctx, "digest_high_water")
	if err != nil {
		t.Fatalf("LockerHighWaterMark (unset): %v", err)
	}
	if found {
		t.Fatalf("expected found=false for a never-set key")
	}

	mark1 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if err := store.SetLockerHighWaterMark(ctx, "digest_high_water", mark1); err != nil {
		t.Fatalf("SetLockerHighWaterMark (insert): %v", err)
	}

	got, found, err := store.LockerHighWaterMark(ctx, "digest_high_water")
	if err != nil {
		t.Fatalf("LockerHighWaterMark: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true after Set")
	}
	if !got.Equal(mark1) {
		t.Fatalf("got %v, want %v", got, mark1)
	}

	// Upsert: a second Set for the same key must update in place, not error or duplicate.
	mark2 := mark1.Add(24 * time.Hour)
	if err := store.SetLockerHighWaterMark(ctx, "digest_high_water", mark2); err != nil {
		t.Fatalf("SetLockerHighWaterMark (update): %v", err)
	}

	got, found, err = store.LockerHighWaterMark(ctx, "digest_high_water")
	if err != nil {
		t.Fatalf("LockerHighWaterMark after update: %v", err)
	}
	if !found || !got.Equal(mark2) {
		t.Fatalf("got %v (found=%v), want %v", got, found, mark2)
	}
}

func TestIsVerified(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	verified, err := store.IsVerified(ctx, "@alice:telecrypt.io")
	if err != nil {
		t.Fatalf("IsVerified (absent): %v", err)
	}
	if verified {
		t.Fatalf("expected false for an mxid never inserted into verified")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO verified (mxid) VALUES ($1)`, "@alice:telecrypt.io"); err != nil {
		t.Fatalf("insert verified row: %v", err)
	}

	verified, err = store.IsVerified(ctx, "@alice:telecrypt.io")
	if err != nil {
		t.Fatalf("IsVerified: %v", err)
	}
	if !verified {
		t.Fatalf("expected true after inserting @alice:telecrypt.io into verified")
	}
}

func TestVerificationGrantProvenance(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()
	team, err := store.CreateTeam(ctx, "@admin:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := store.InsertSeat(ctx, team.ID, "@seat:telecrypt.io"); err != nil {
		t.Fatalf("InsertSeat: %v", err)
	}
	if err := store.InsertVerified(ctx, "@manual:telecrypt.io"); err != nil {
		t.Fatalf("InsertVerified manual: %v", err)
	}
	if err := store.InsertBillingVerificationGrant(ctx, team.ID, "@seat:telecrypt.io"); err != nil {
		t.Fatalf("InsertBillingVerificationGrant: %v", err)
	}

	set, err := store.VerifiedMXIDs(ctx)
	if err != nil {
		t.Fatalf("VerifiedMXIDs: %v", err)
	}
	if !set["@manual:telecrypt.io"] || !set["@seat:telecrypt.io"] || len(set) != 2 {
		t.Fatalf("effective verification set = %v, want manual and billing grants", set)
	}
	if manual, err := store.HasManualVerificationGrant(ctx, "@seat:telecrypt.io"); err != nil || manual {
		t.Fatalf("billing seat manual grant = %v, %v; want false, nil", manual, err)
	}
	if billing, err := store.HasBillingVerificationGrant(ctx, "@seat:telecrypt.io"); err != nil || !billing {
		t.Fatalf("billing seat billing grant = %v, %v; want true, nil", billing, err)
	}

	// The composite foreign key rejects a grant whose mxid is not an attached seat of team.
	if err := store.InsertBillingVerificationGrant(ctx, team.ID, "@not-a-seat:telecrypt.io"); err == nil {
		t.Fatal("billing grant for an unattached mxid unexpectedly succeeded")
	}

	if err := store.DeleteBillingVerificationGrant(ctx, "@seat:telecrypt.io"); err != nil {
		t.Fatalf("DeleteBillingVerificationGrant: %v", err)
	}
	verified, err := store.IsVerified(ctx, "@seat:telecrypt.io")
	if err != nil || verified {
		t.Fatalf("IsVerified after billing removal = %v, %v; want false, nil", verified, err)
	}

	// Existing verified rows are manual grants and are untouched by billing operations.
	if _, err := pool.Exec(ctx, `INSERT INTO verified (mxid) VALUES ($1)`, "@both:telecrypt.io"); err != nil {
		t.Fatalf("insert second manual grant: %v", err)
	}
	if err := store.InsertSeat(ctx, team.ID, "@both:telecrypt.io"); err != nil {
		t.Fatalf("InsertSeat both: %v", err)
	}
	if err := store.InsertBillingVerificationGrant(ctx, team.ID, "@both:telecrypt.io"); err != nil {
		t.Fatalf("InsertBillingVerificationGrant both: %v", err)
	}
	if err := store.DeleteBillingVerificationGrant(ctx, "@both:telecrypt.io"); err != nil {
		t.Fatalf("DeleteBillingVerificationGrant both: %v", err)
	}
	verified, err = store.IsVerified(ctx, "@both:telecrypt.io")
	if err != nil || !verified {
		t.Fatalf("manual grant after billing removal = %v, %v; want true, nil", verified, err)
	}
}

func TestTeamAndSeatInvariants(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	team, err := store.CreateTeam(ctx, "@admin:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := store.CreateTeam(ctx, "@admin:telecrypt.io"); err == nil {
		t.Fatal("duplicate team admin unexpectedly succeeded")
	}

	if err := store.InsertSeat(ctx, team.ID, "@seat:telecrypt.io"); err != nil {
		t.Fatalf("InsertSeat: %v", err)
	}
	if err := store.InsertBillingVerificationGrant(ctx, team.ID, "@seat:telecrypt.io"); err != nil {
		t.Fatalf("InsertBillingVerificationGrant: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, team.ID); err != nil {
		t.Fatalf("delete team: %v", err)
	}
	var grants int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM billing_verification_grants WHERE mxid = $1`, "@seat:telecrypt.io").Scan(&grants); err != nil {
		t.Fatalf("count cascaded grants: %v", err)
	}
	if grants != 0 {
		t.Fatalf("team deletion left %d billing grants", grants)
	}

	first, err := store.CreateTeam(ctx, "@first:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam first: %v", err)
	}
	second, err := store.CreateTeam(ctx, "@second:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam second: %v", err)
	}
	subscriptionID := "sub_unique"
	if err := store.UpdateTeamSubscription(ctx, first.ID, "active", 1, nil, &subscriptionID); err != nil {
		t.Fatalf("bind first subscription: %v", err)
	}
	if err := store.UpdateTeamSubscription(ctx, second.ID, "active", 1, nil, &subscriptionID); err == nil {
		t.Fatal("duplicate non-null Dodo subscription unexpectedly succeeded")
	}
	if err := store.UpdateTeamSubscription(ctx, first.ID, "not-a-status", 1, nil, nil); err == nil {
		t.Fatal("invalid subscription status unexpectedly succeeded")
	}
	if err := store.UpdateTeamSubscription(ctx, first.ID, "active", -1, nil, nil); err == nil {
		t.Fatal("negative paid seats unexpectedly succeeded")
	}
}

func TestAttachSeatEnforcesCapacity(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()
	team, err := store.CreateTeam(ctx, "@capacity-admin:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE teams SET paid_seats = 1 WHERE id = $1`, team.ID); err != nil {
		t.Fatalf("set paid seats: %v", err)
	}
	if err := store.AttachSeat(ctx, team.ID, "@first:telecrypt.io"); err != nil {
		t.Fatalf("first AttachSeat: %v", err)
	}
	if err := store.AttachSeat(ctx, team.ID, "@second:telecrypt.io"); !errors.Is(err, ErrSeatCapacityReached) {
		t.Fatalf("second AttachSeat error = %v, want ErrSeatCapacityReached", err)
	}
}

func TestAttachSeatSerializesConcurrentCapacityChecks(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()
	team, err := store.CreateTeam(ctx, "@concurrent-seat-admin:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE teams SET paid_seats = 1 WHERE id = $1`, team.ID); err != nil {
		t.Fatalf("set paid seats: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, mxid := range []string{"@first-racer:telecrypt.io", "@second-racer:telecrypt.io"} {
		go func(mxid string) {
			<-start
			results <- store.AttachSeat(ctx, team.ID, mxid)
		}(mxid)
	}
	close(start)

	var attached, rejected int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			attached++
		case errors.Is(err, ErrSeatCapacityReached):
			rejected++
		default:
			t.Fatalf("unexpected concurrent AttachSeat error: %v", err)
		}
	}
	if attached != 1 || rejected != 1 {
		t.Fatalf("concurrent results: attached=%d rejected=%d, want 1/1", attached, rejected)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM seats WHERE team_id = $1`, team.ID).Scan(&count); err != nil {
		t.Fatalf("count seats: %v", err)
	}
	if count != 1 {
		t.Fatalf("stored seats = %d, want 1", count)
	}
}

func TestBeginCheckoutSerializesConcurrentAttempts(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	team, err := store.CreateTeam(ctx, "@concurrent-checkout-admin:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	start := make(chan struct{})
	type checkoutResult struct {
		reservation CheckoutReservation
		err         error
	}
	results := make(chan checkoutResult, 2)
	for range 2 {
		go func() {
			<-start
			reservation, err := store.BeginCheckout(ctx, team.ID, 2, time.Now().UTC())
			results <- checkoutResult{reservation: reservation, err: err}
		}()
	}
	close(start)

	var attempts []uuid.UUID
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("unexpected concurrent BeginCheckout error: %v", result.err)
		}
		attempts = append(attempts, result.reservation.AttemptID)
	}
	if attempts[0] == uuid.Nil || attempts[0] != attempts[1] {
		t.Fatalf("concurrent attempts = %v, want one shared durable id", attempts)
	}
}

func TestPendingDowngradeCapacityBlocksConcurrentAttachment(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()
	team, err := store.CreateTeam(ctx, "@downgrade-admin:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE teams SET subscription_status = 'active', paid_seats = 3, dodo_subscription_id = 'sub_downgrade'
		WHERE id = $1
	`, team.ID); err != nil {
		t.Fatalf("activate team: %v", err)
	}
	if err := store.AttachSeat(ctx, team.ID, "@first:telecrypt.io"); err != nil {
		t.Fatalf("AttachSeat first: %v", err)
	}
	reservation, err := store.ReserveSeatCountChange(ctx, team.ID, 1, time.Now().UTC())
	if err != nil {
		t.Fatalf("ReserveSeatCountChange: %v", err)
	}
	if reservation.Attached != 1 || reservation.AttemptID == uuid.Nil {
		t.Fatalf("reservation = %+v, want one attached and durable attempt id", reservation)
	}
	retry, err := store.ReserveSeatCountChange(ctx, team.ID, 1, time.Now().UTC())
	if err != nil {
		t.Fatalf("repeat ReserveSeatCountChange: %v", err)
	}
	if !retry.Reused || retry.AttemptID != reservation.AttemptID {
		t.Fatalf("repeated reservation = %+v, want reused attempt %s", retry, reservation.AttemptID)
	}
	if err := store.AttachSeat(ctx, team.ID, "@racer:telecrypt.io"); !errors.Is(err, ErrSeatCapacityReached) {
		t.Fatalf("AttachSeat during downgrade = %v, want ErrSeatCapacityReached", err)
	}
}

func TestTerminalSubscriptionCannotBeRevivedByDelayedEvent(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	team, err := store.CreateTeam(ctx, "@terminal-admin:telecrypt.io")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := store.BeginCheckout(ctx, team.ID, 2, time.Now().UTC()); err != nil {
		t.Fatalf("BeginCheckout: %v", err)
	}
	if err := store.BindCurrentSubscription(ctx, team.ID, "sub_terminal", "cus_terminal", "active", 2); err != nil {
		t.Fatalf("bind active: %v", err)
	}
	if err := store.BindCurrentSubscription(ctx, team.ID, "sub_terminal", "cus_terminal", "cancelled", 2); err != nil {
		t.Fatalf("bind cancelled: %v", err)
	}
	if err := store.BindCurrentSubscription(ctx, team.ID, "sub_terminal", "cus_terminal", "active", 2); !errors.Is(err, ErrStaleSubscription) {
		t.Fatalf("delayed active event = %v, want ErrStaleSubscription", err)
	}
	got, err := store.GetTeamByID(ctx, team.ID)
	if err != nil {
		t.Fatalf("GetTeamByID: %v", err)
	}
	if got.SubscriptionStatus != "cancelled" {
		t.Fatalf("subscription status = %q, want cancelled", got.SubscriptionStatus)
	}
}
