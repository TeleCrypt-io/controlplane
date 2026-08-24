package db

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	janitorSchema     = "janitor"
	janitorSearchPath = "pg_catalog, janitor, pg_temp"
)

var ambientPostgresSettings = []string{
	"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
	"PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT",
	"PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLSNI", "PGSSLNEGOTIATION",
	"PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS",
	"PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGCHANNELBINDING", "PGREQUIREAUTH",
}

// OpenJanitorPool gives Janitor's connections one explicit private application schema while
// resolving PostgreSQL built-ins before any role-owned object. All Janitor writes are schema
// qualified, so catalog-first lookup removes a shadowing surface without changing ownership.
func OpenJanitorPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	for _, name := range ambientPostgresSettings {
		if _, present := os.LookupEnv(name); present {
			return nil, fmt.Errorf("ambient %s is not allowed; use JANITOR_DB_URL", name)
		}
	}
	// Validate before pgx parses the URL. pgx accepts service and filesystem
	// parameters, so parsing first would let an unsafe URL read local files or
	// redirect the connection before this package can enforce Janitor's boundary.
	if err := ValidateJanitorDatabaseURL(databaseURL); err != nil {
		return nil, fmt.Errorf("validate janitor database URL: %w", err)
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse janitor database URL")
	}
	// Do not allow a connection-string `options` parameter to issue a later SET and
	// redirect unqualified maintenance queries into another schema. Janitor has no
	// need for arbitrary startup options; its private search path is fixed here.
	delete(poolConfig.ConnConfig.RuntimeParams, "options")
	poolConfig.ConnConfig.RuntimeParams["search_path"] = janitorSearchPath
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open janitor database pool")
	}
	return pool, nil
}
