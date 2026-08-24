package db

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestJanitorDatabaseContractPG17(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping real-Postgres role/view test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		DROP SCHEMA IF EXISTS cashier CASCADE;
		DROP SCHEMA IF EXISTS janitor CASCADE;
		CREATE SCHEMA janitor;
		REVOKE ALL ON SCHEMA janitor FROM PUBLIC;
		CREATE SCHEMA cashier;
		REVOKE ALL ON SCHEMA cashier FROM PUBLIC;
		CREATE TABLE cashier.identity_source (singleton BOOLEAN PRIMARY KEY, server_name TEXT NOT NULL, billing_environment TEXT NOT NULL);
		INSERT INTO cashier.identity_source VALUES (TRUE, 'stage.telecrypt.io', 'test');
		CREATE VIEW cashier.janitor_lock_exclusions WITH (security_barrier = true) AS SELECT '@paid:stage.telecrypt.io'::TEXT AS mxid;
		CREATE VIEW cashier.janitor_deployment_identity WITH (security_barrier = true) AS SELECT server_name, billing_environment FROM cashier.identity_source;
	`); err != nil {
		t.Fatalf("prepare view fixture: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var current string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&current); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	if err := ValidateJanitorDatabaseContract(ctx, pool, current); err != nil {
		t.Fatalf("ValidateJanitorDatabaseContract: %v", err)
	}
	store := NewStore(pool)
	if err := store.VerifyDeploymentIdentity(ctx, "stage.telecrypt.io", "test"); err != nil {
		t.Fatalf("VerifyDeploymentIdentity: %v", err)
	}
	exclusions, err := store.LockExclusions(ctx)
	if err != nil || len(exclusions) != 1 {
		t.Fatalf("LockExclusions = %#v, %v", exclusions, err)
	}
}
