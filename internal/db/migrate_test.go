// TestMigrate requires a real Postgres reachable at TEST_DATABASE_URL — skipped automatically if
// the env var isn't set.
//
//	docker run -d -e POSTGRES_PASSWORD=test -e POSTGRES_DB=testdb -p 15432:5432 postgres:17-alpine
//	TEST_DATABASE_URL="postgres://postgres:test@localhost:15432/testdb" go test ./internal/db/...
package db

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrate is a smoke test for the migration runner itself: applying 0001_init.sql from a
// clean database must succeed, create the three tables the target schema defines, and be
// idempotent (a second Migrate call against the same DB is a no-op, not an error).
func TestMigrate(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	// Start from a clean slate so this test is repeatable against a long-lived test DB.
	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS dodo_subscription_bindings, billing_verification_grants, seats, teams, ownership, verified, pending_claims, locker_state, schema_migrations`,
	); err != nil {
		t.Fatalf("drop existing tables: %v", err)
	}

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// ownership/pending_claims are created by 0001_init.sql and dropped by 0003_drop_adopt.sql —
	// migrating from clean must leave them absent, not present.
	for _, table := range []string{"ownership", "pending_claims"} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if exists {
			t.Errorf("expected table %q to be dropped by 0003_drop_adopt.sql, but it exists", table)
		}
	}

	for _, table := range []string{"verified", "billing_verification_grants", "locker_state", "teams", "seats", "dodo_subscription_bindings"} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("expected table %q to exist after Migrate", table)
		}
	}

	// Re-running Migrate against an already-migrated DB must be a no-op, not an error.
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second Migrate call: %v", err)
	}
}

// TestMigrateUpgradeFromTeamsSeats exercises the path the live database takes: 0001 through
// 0004 are already recorded, then 0005 must replace the seat FK and add provenance/invariants
// without requiring a clean database.
func TestMigrateUpgradeFromTeamsSeats(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS dodo_subscription_bindings, billing_verification_grants, seats, teams, ownership, verified, pending_claims, locker_state, schema_migrations`,
	); err != nil {
		t.Fatalf("drop existing tables: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, name := range []string{
		"0001_init.sql",
		"0002_locker_state.sql",
		"0003_drop_adopt.sql",
		"0004_teams_seats.sql",
	} {
		sql, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply pre-0005 %s: %v", name, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			t.Fatalf("record pre-0005 %s: %v", name, err)
		}
	}

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("upgrade from 0004: %v", err)
	}

	var applied bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = '0005_verification_grants_and_team_invariants.sql')`).Scan(&applied); err != nil {
		t.Fatalf("check 0005 applied: %v", err)
	}
	if !applied {
		t.Fatal("0005 migration was not recorded")
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = '0007_cashier_lifecycle_hardening.sql')`).Scan(&applied); err != nil {
		t.Fatalf("check 0007 applied: %v", err)
	}
	if !applied {
		t.Fatal("0007 migration was not recorded")
	}

	var cascade bool
	if err := pool.QueryRow(ctx, `
		SELECT confdeltype = 'c'
		FROM pg_constraint
		WHERE conrelid = 'seats'::regclass AND confrelid = 'teams'::regclass AND contype = 'f'
	`).Scan(&cascade); err != nil {
		t.Fatalf("inspect upgraded seats FK: %v", err)
	}
	if !cascade {
		t.Fatal("upgraded seats FK is not ON DELETE CASCADE")
	}
}
