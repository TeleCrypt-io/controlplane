package db

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenJanitorPoolUsesPrivateSchema(t *testing.T) {
	pool, err := OpenJanitorPool(context.Background(), "postgres://janitor:secret@example.test/database?sslmode=require&connect_timeout=5&application_name=janitor")
	if err != nil {
		t.Fatalf("OpenJanitorPool: %v", err)
	}
	defer pool.Close()
	if got, want := pool.Config().ConnConfig.RuntimeParams["search_path"], janitorSearchPath; got != want {
		t.Fatalf("search_path = %q, want %q", got, want)
	}
	if _, present := pool.Config().ConnConfig.RuntimeParams["options"]; present {
		t.Fatal("OpenJanitorPool retained arbitrary connection options")
	}
}

func TestOpenJanitorPoolRejectsServicefileBeforeFilesystemRead(t *testing.T) {
	serviceFile := filepath.Join(t.TempDir(), "service.conf")
	if err := os.WriteFile(serviceFile, []byte("[redirected]\nhost=redirected.example\n"), 0o600); err != nil {
		t.Fatalf("write service file: %v", err)
	}
	databaseURL := "postgres://janitor:secret@example.test/database?servicefile=" + url.QueryEscape(serviceFile) + "&service=redirected"
	_, err := OpenJanitorPool(context.Background(), databaseURL)
	if err == nil || !strings.Contains(err.Error(), `query parameter "servicefile"`) {
		t.Fatalf("OpenJanitorPool error = %v, want pre-parse servicefile rejection", err)
	}
	if strings.Contains(err.Error(), "failed to read service") {
		t.Fatalf("OpenJanitorPool parsed servicefile before rejecting it: %v", err)
	}
}

func TestOpenJanitorPoolRejectsAmbientPostgresSettings(t *testing.T) {
	t.Setenv("PGSERVICE", "redirected")
	_, err := OpenJanitorPool(context.Background(), "postgres://janitor:secret@example.test/database")
	if err == nil || !strings.Contains(err.Error(), "ambient PGSERVICE") {
		t.Fatalf("OpenJanitorPool error = %v, want ambient PGSERVICE rejection", err)
	}
}

func TestOpenJanitorPoolRejectsPresentEmptyAmbientPostgresSettings(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	_, err := OpenJanitorPool(context.Background(), "postgres://janitor:secret@example.test/database")
	if err == nil || !strings.Contains(err.Error(), "ambient PGSERVICE") {
		t.Fatalf("OpenJanitorPool error = %v, want present empty PGSERVICE rejection", err)
	}
}

func TestOpenJanitorPoolRejectsUnsafeQueryOptions(t *testing.T) {
	for _, query := range []string{
		"servicefile=/tmp/service.conf",
		"passfile=/tmp/passfile",
		"sslkey=/tmp/client.key",
		"sslcert=/tmp/client.crt",
		"sslrootcert=/tmp/root.crt",
		"host=other.example",
		"hostaddr=127.0.0.1",
		"port=6543",
		"user=other",
		"database=other",
		"dbname=other",
		"service=other",
		"options=-c%20search_path%3Dpublic",
		"search_path=public",
		"unknown=value",
		"sslmode=require&sslmode=disable",
		"%73slmode=require",
		"sslmode=",
		"sslmode=%20",
		"sslmode=require&",
	} {
		t.Run(query, func(t *testing.T) {
			_, err := OpenJanitorPool(context.Background(), "postgres://janitor:secret@example.test/database?"+query)
			if err == nil {
				t.Fatalf("OpenJanitorPool accepted unsafe query %q", query)
			}
		})
	}
}

func TestValidateJanitorDatabaseURLRejectsWhitespaceAndEncodedTargets(t *testing.T) {
	base := "postgres://janitor:secret@example.test/database"
	for _, raw := range []string{
		base + "?sslmode=require%20",
		base + "?application_name=janitor%20sweep",
		base + "?application_name=janitor%09sweep",
		base + "?application_name=janitor%0Asweep",
		base + "?sslmode=require&&application_name=janitor",
		base + "?sslmode=require&application_name",
		base + "?sslmode=require%ZZ",
		"POSTGRES://janitor@example.test/database",
		base + "#",
		"postgres://janitor@example.test:1:2/database",
		"postgres://jan%69tor@example.test/database",
		"postgres://janitor@EXAMPLE.test/database",
		"postgres://janitor@example.test./database",
		"postgres://janitor@example..test/database",
		"postgres://janitor@example.test:05432/database",
		"postgres://janitor@example.test:0/database",
		"postgres://janitor@example.test:65536/database",
		"postgres://janitor@example.test:/database",
		"postgres://janitor@example.test//database",
		"postgres://janitor@example.test/database/",
		"postgres://JANITOR@example.test/database",
		"postgres://janitor@example.test/Database",
		" " + base,
		base + " ",
		base + "?",
		"postgres://janitor@example.test/database",
		"postgres://janitor:@example.test/database",
		"postgres://janitor:secret%20password@example.test/database",
		"postgres://janitor:secret%09password@example.test/database",
		"postgres://janitor:secret%0Apassword@example.test/database",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateJanitorDatabaseURL(raw); err == nil {
				t.Fatalf("ValidateJanitorDatabaseURL accepted %q", raw)
			}
		})
	}
}

func TestValidateJanitorDatabaseURLAllowsCanonicalAuthorityForms(t *testing.T) {
	for _, raw := range []string{
		"postgresql://janitor:secret@example.test:5432/database",
		"postgres://janitor:p%40ss@example.test/database?sslmode=require&connect_timeout=5&application_name=janitor-sweep",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateJanitorDatabaseURL(raw); err != nil {
				t.Fatalf("ValidateJanitorDatabaseURL: %v", err)
			}
		})
	}
}
