package db

import (
    "context"
    "os"
    "testing"

    "github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrate covers the public, Janitor-owned schema only. Billing tables are created and
// migrated by private Cashier and must never be reintroduced from this repository.
func TestMigrate(t *testing.T) {
    dsn := os.Getenv("TEST_DATABASE_URL")
    if dsn == "" { t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test") }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, dsn)
    if err != nil { t.Fatalf("pgxpool.New: %v", err) }
    defer pool.Close()
    if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS ownership, pending_claims, verified, locker_state, schema_migrations`); err != nil { t.Fatalf("drop existing tables: %v", err) }
    if err := Migrate(ctx, pool); err != nil { t.Fatalf("Migrate: %v", err) }
    for _, table := range []string{"verified", "locker_state", "schema_migrations"} {
        var exists bool
        if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table).Scan(&exists); err != nil { t.Fatalf("check table %s: %v", table, err) }
        if !exists { t.Errorf("expected table %q after Migrate", table) }
    }
    for _, table := range []string{"ownership", "pending_claims", "teams", "seats", "billing_environment_guard"} {
        var exists bool
        if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table).Scan(&exists); err != nil { t.Fatalf("check table %s: %v", table, err) }
        if exists { t.Errorf("public migration must not create %q", table) }
    }
    if err := Migrate(ctx, pool); err != nil { t.Fatalf("second Migrate: %v", err) }
}
