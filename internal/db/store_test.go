package db

import (
    "context"
    "os"
    "testing"

    "github.com/jackc/pgx/v5/pgxpool"
)

func testStore(t *testing.T) (*Store, context.Context) {
    t.Helper()
    dsn := os.Getenv("TEST_DATABASE_URL")
    if dsn == "" { t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres test") }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, dsn)
    if err != nil { t.Fatalf("pgxpool.New: %v", err) }
    t.Cleanup(pool.Close)
    if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS cashier CASCADE; DROP TABLE IF EXISTS ownership, pending_claims, verified, locker_state, schema_migrations`); err != nil { t.Fatalf("reset database: %v", err) }
    if err := Migrate(ctx, pool); err != nil { t.Fatalf("Migrate: %v", err) }
    if _, err := pool.Exec(ctx, `CREATE SCHEMA cashier; CREATE TABLE cashier.billing_environment_guard (singleton BOOLEAN PRIMARY KEY, billing_env TEXT NOT NULL, matrix_deployment_id TEXT NOT NULL); CREATE TABLE cashier.billing_verification_grants (mxid TEXT PRIMARY KEY)`); err != nil { t.Fatalf("create private cashier test schema: %v", err) }
    return NewStore(pool), ctx
}

func TestStoreReadsButDoesNotCreatePrivateCashierState(t *testing.T) {
    store, ctx := testStore(t)
    if _, err := store.BindBillingEnvironment(ctx, "test", "production"); err == nil { t.Fatal("accepted missing private Cashier billing guard") }
    pool := store.pool
    if _, err := pool.Exec(ctx, `INSERT INTO cashier.billing_environment_guard (singleton, billing_env, matrix_deployment_id) VALUES (TRUE, 'test', 'production')`); err != nil { t.Fatalf("insert guard: %v", err) }
    if err := store.BindBillingEnvironment(ctx, "test", "production"); err != nil { t.Fatalf("verify guard: %v", err) }
    if err := store.BindBillingEnvironment(ctx, "production", "production"); err == nil { t.Fatal("accepted mismatched billing guard") }
}

func TestStoreCombinesManualAndPrivateCashierVerificationGrants(t *testing.T) {
    store, ctx := testStore(t)
    if _, err := store.pool.Exec(ctx, `INSERT INTO verified (mxid) VALUES ('@manual:telecrypt.io'); INSERT INTO cashier.billing_verification_grants (mxid) VALUES ('@billing:telecrypt.io')`); err != nil { t.Fatalf("insert grants: %v", err) }
    verified, err := store.VerifiedMXIDs(ctx)
    if err != nil { t.Fatalf("VerifiedMXIDs: %v", err) }
    if !verified["@manual:telecrypt.io"] || !verified["@billing:telecrypt.io"] { t.Fatalf("missing expected grants: %#v", verified) }
    if got, err := store.IsVerified(ctx, "@billing:telecrypt.io"); err != nil || !got { t.Fatalf("IsVerified billing grant = %v, %v", got, err) }
}
