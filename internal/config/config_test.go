package config

import (
	"strings"
	"testing"
)

func setRequiredStewardEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SERVER_NAME":                   "telecrypt.test",
		"BILLING_ENV":                   "test",
		"BACKEND_PUBLIC_URL":            "https://backend.test.telecrypt.io",
		"MAS_OIDC_CLIENT_ID":            "steward",
		"MAS_OIDC_CLIENT_SECRET":        "test-secret",
		"SESSION_KEY":                   strings.Repeat("s", 32),
		"STEWARD_ASSERTION_PRIVATE_KEY": strings.Repeat("A", 86),
	} {
		t.Setenv(key, value)
	}
}

func TestLoadStewardUsesFixedPrivateTopologyAndDerivedPublicURLs(t *testing.T) {
	setRequiredStewardEnv(t)
	cfg, err := LoadSteward()
	if err != nil {
		t.Fatalf("LoadSteward: %v", err)
	}
	if got, want := cfg.BackendPublicURL, "https://backend.test.telecrypt.io"; got != want {
		t.Fatalf("BackendPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.PlanPublicURL, "https://backend.test.telecrypt.io/plan"; got != want {
		t.Fatalf("PlanPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.MASInternalURL, "http://mas:8080"; got != want {
		t.Fatalf("MASInternalURL = %q, want %q", got, want)
	}
	if got, want := cfg.CashierInternalURL, "http://cashier:9011"; got != want {
		t.Fatalf("CashierInternalURL = %q, want %q", got, want)
	}
}

func TestLoadStewardRequiresBackendOrigin(t *testing.T) {
	setRequiredStewardEnv(t)
	t.Setenv("BACKEND_PUBLIC_URL", "")
	if _, err := LoadSteward(); err == nil || !strings.Contains(err.Error(), "BACKEND_PUBLIC_URL") {
		t.Fatalf("LoadSteward error = %v, want missing BACKEND_PUBLIC_URL", err)
	}
}

func TestLoadStewardRejectsShortSessionKey(t *testing.T) {
	setRequiredStewardEnv(t)
	t.Setenv("SESSION_KEY", "too-short")
	if _, err := LoadSteward(); err == nil {
		t.Fatal("LoadSteward accepted a short session signing key")
	}
}

func TestLoadLockerRequiresServerNameAndBillingEnvironment(t *testing.T) {
	for key, value := range map[string]string{
		"BILLING_ENV":             "sandbox",
		"MAS_ADMIN_CLIENT_ID":     "janitor",
		"MAS_ADMIN_CLIENT_SECRET": "secret",
		"JANITOR_DB_URL":          "postgres://janitor@db/test",
		"SERVER_NAME":             "telecrypt.test",
	} {
		t.Setenv(key, value)
	}
	if _, err := LoadLocker(); err == nil {
		t.Fatal("LoadLocker accepted invalid billing environment")
	}
}

func TestLoadLockerUsesFixedMASAdminEndpoint(t *testing.T) {
	for key, value := range map[string]string{
		"BILLING_ENV":             "test",
		"MAS_ADMIN_CLIENT_ID":     "janitor",
		"MAS_ADMIN_CLIENT_SECRET": "secret",
		"JANITOR_DB_URL":          "postgres://janitor@db/test",
		"SERVER_NAME":             "telecrypt.test",
	} {
		t.Setenv(key, value)
	}
	cfg, err := LoadLocker()
	if err != nil {
		t.Fatalf("LoadLocker: %v", err)
	}
	if got, want := cfg.MASAdminURL, "http://mas:8081"; got != want {
		t.Fatalf("MASAdminURL = %q, want %q", got, want)
	}
}

func TestLoadLockerRejectsInvalidDatabaseURL(t *testing.T) {
	for key, value := range map[string]string{
		"BILLING_ENV":             "test",
		"MAS_ADMIN_CLIENT_ID":     "janitor",
		"MAS_ADMIN_CLIENT_SECRET": "secret",
		"JANITOR_DB_URL":          "https://db.invalid",
		"SERVER_NAME":             "telecrypt.test",
	} {
		t.Setenv(key, value)
	}
	if _, err := LoadLocker(); err == nil || !strings.Contains(err.Error(), "JANITOR_DB_URL") {
		t.Fatalf("LoadLocker error = %v, want explicit Postgres URL error", err)
	}
}

func TestLoadRequiresBackendOrigin(t *testing.T) {
	t.Setenv("BACKEND_PUBLIC_URL", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "BACKEND_PUBLIC_URL") {
		t.Fatalf("Load error = %v, want missing backend origin", err)
	}
}

func TestValidateRedpillUsesDerivedPublicEndpoints(t *testing.T) {
	t.Setenv("BACKEND_PUBLIC_URL", "https://backend.telecrypt.io")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.ServerName = "telecrypt.io"
	if err := cfg.ValidateRedpill(); err != nil {
		t.Fatalf("ValidateRedpill rejected a valid configuration: %v", err)
	}
	cfg.MASPublicURL = "http://mas:8080"
	if err := cfg.ValidateRedpill(); err == nil {
		t.Fatal("ValidateRedpill accepted an internal MAS endpoint")
	}
}
