// TestStore requires a real Postgres reachable at TEST_DATABASE_URL — skipped automatically if the
// env var isn't set. See migrate_test.go's header for how to stand up a throwaway Postgres.
package db

import (
	"context"
	"os"
	"testing"
	"time"

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
		DROP TABLE IF EXISTS billing_verification_grants, seats, teams, ownership, verified, pending_claims, locker_state, schema_migrations`,
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
