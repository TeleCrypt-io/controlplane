package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

const (
	testPlanClientID    = "01J00000000000000000000000"
	testJanitorClientID = "01J00000000000000000000001"
)

func testPlanPrivateKey() string {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed))
}

func setRequiredPlanEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SERVER_NAME":                "stage.telecrypt.io",
		"BILLING_ENVIRONMENT":        "test",
		"MAS_OIDC_CLIENT_ID":         testPlanClientID,
		"MAS_OIDC_CLIENT_SECRET":     "test-secret",
		"PLAN_SESSION_KEY":           strings.Repeat("s", 32),
		"PLAN_ASSERTION_PRIVATE_KEY": testPlanPrivateKey(),
	} {
		t.Setenv(key, value)
	}
}

func setRequiredJanitorEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"JANITOR_DRY_RUN":         "1",
		"MAS_ADMIN_CLIENT_ID":     testJanitorClientID,
		"MAS_ADMIN_CLIENT_SECRET": "secret",
		"JANITOR_DB_URL":          "postgres://telecrypt_janitor_stage_user:secret@db/telecrypt_billing_stage",
		"SERVER_NAME":             "stage.telecrypt.io",
		"BILLING_ENVIRONMENT":     "test",
		"SMTP_HOST":               "",
		"SMTP_USERNAME":           "",
		"SMTP_PASSWORD":           "",
		"SMTP_FROM":               "",
		"OWNER_EMAIL":             "",
	} {
		t.Setenv(key, value)
	}
}

func setLiveJanitorEnv(t *testing.T) {
	t.Helper()
	setRequiredJanitorEnv(t)
	t.Setenv("SERVER_NAME", "telecrypt.io")
	t.Setenv("BILLING_ENVIRONMENT", "live")
	t.Setenv("JANITOR_DRY_RUN", "0")
	t.Setenv("JANITOR_DB_URL", "postgres://telecrypt_janitor_user:secret@db/telecrypt_billing")
	t.Setenv("SMTP_HOST", "smtp.example.test")
	t.Setenv("SMTP_USERNAME", "janitor@example.test")
	t.Setenv("SMTP_PASSWORD", "smtp-secret")
	t.Setenv("SMTP_FROM", "noreply@example.test")
	t.Setenv("OWNER_EMAIL", "owner@example.test")
}

func TestLoadPlanDerivesPublicURLsFromServerName(t *testing.T) {
	setRequiredPlanEnv(t)
	cfg, err := LoadPlan()
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	if got, want := cfg.BackendPublicURL, "https://backend.stage.telecrypt.io"; got != want {
		t.Fatalf("BackendPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.PlanPublicURL, "https://backend.stage.telecrypt.io/plan"; got != want {
		t.Fatalf("PlanPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.MASInternalURL, "http://mas:8080"; got != want {
		t.Fatalf("MASInternalURL = %q, want %q", got, want)
	}
	if got, want := cfg.CashierInternalURL, "http://cashier:9011"; got != want {
		t.Fatalf("CashierInternalURL = %q, want %q", got, want)
	}
}

func TestLoadPlanRequiresExactBillingProfiles(t *testing.T) {
	for _, tc := range []struct {
		server, billing string
		valid           bool
	}{
		{"telecrypt.io", "test", true}, {"stage.telecrypt.io", "test", true}, {"telecrypt.io", "live", true},
		{"stage.telecrypt.io", "live", false}, {"preview.telecrypt.io", "test", false}, {"telecrypt.io", "production", false},
	} {
		t.Run(tc.server+"/"+tc.billing, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv("SERVER_NAME", tc.server)
			t.Setenv("BILLING_ENVIRONMENT", tc.billing)
			_, err := LoadPlan()
			if (err == nil) != tc.valid {
				t.Fatalf("LoadPlan validity = %v, want %v (err=%v)", err == nil, tc.valid, err)
			}
		})
	}
	setRequiredPlanEnv(t)
	t.Setenv("BILLING_ENV", "test")
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "BILLING_ENV") {
		t.Fatal("LoadPlan accepted legacy BILLING_ENV override")
	}
	if err := os.Unsetenv("BILLING_ENV"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DODO_API_URL", "DODO_MODE", "DODO_API_KEY", "DODO_WEBHOOK_SECRET"} {
		t.Run(name, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv(name, "ambient-value")
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadPlan accepted ambient Dodo setting %s", name)
			}
		})
	}
}

func TestLoadPlanRequiresServerName(t *testing.T) {
	setRequiredPlanEnv(t)
	t.Setenv("SERVER_NAME", "")
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "SERVER_NAME") {
		t.Fatalf("LoadPlan error = %v, want missing SERVER_NAME", err)
	}
}

func TestLoadPlanRequiresCanonicalMASClientULID(t *testing.T) {
	for _, value := range []string{"plan", "81J00000000000000000000000", "01j00000000000000000000000", "01J0000000000000000000000I"} {
		t.Run(value, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv("MAS_OIDC_CLIENT_ID", value)
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "MAS_OIDC_CLIENT_ID") {
				t.Fatalf("LoadPlan error = %v, want canonical MAS client ULID rejection", err)
			}
		})
	}
}

func TestLoadPlanRejectsShortPlanSessionKey(t *testing.T) {
	setRequiredPlanEnv(t)
	t.Setenv("PLAN_SESSION_KEY", "too-short")
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "PLAN_SESSION_KEY") {
		t.Fatal("LoadPlan accepted a short session signing key")
	}
}

func TestLoadPlanRejectsSurroundingWhitespaceInSecrets(t *testing.T) {
	for _, name := range []string{"MAS_OIDC_CLIENT_ID", "MAS_OIDC_CLIENT_SECRET", "PLAN_SESSION_KEY", "PLAN_ASSERTION_PRIVATE_KEY"} {
		t.Run(name, func(t *testing.T) {
			setRequiredPlanEnv(t)
			value := " secret "
			if name == "PLAN_SESSION_KEY" {
				value = " " + strings.Repeat("s", 32)
			}
			if name == "PLAN_ASSERTION_PRIVATE_KEY" {
				value = " " + testPlanPrivateKey()
			}
			t.Setenv(name, value)
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadPlan error = %v, want %s whitespace rejection", err, name)
			}
		})
	}
}

func TestLoadPlanRejectsLegacySessionKeyName(t *testing.T) {
	setRequiredPlanEnv(t)
	t.Setenv("SESSION_KEY", strings.Repeat("s", 32))
	if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "SESSION_KEY") {
		t.Fatalf("LoadPlan error = %v, want legacy SESSION_KEY rejection", err)
	}
}

func TestLoadPlanRejectsInvalidPrivateKeyMaterial(t *testing.T) {
	for _, value := range []string{
		strings.Repeat("A", 86),
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)),
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)) + "=",
	} {
		t.Run(value, func(t *testing.T) {
			setRequiredPlanEnv(t)
			t.Setenv("PLAN_ASSERTION_PRIVATE_KEY", value)
			if _, err := LoadPlan(); err == nil || !strings.Contains(err.Error(), "PLAN_ASSERTION_PRIVATE_KEY") {
				t.Fatalf("LoadPlan error = %v, want invalid PLAN_ASSERTION_PRIVATE_KEY rejection", err)
			}
		})
	}
}

func TestServerIdentityDerivesFrozenPublicHostnames(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		valid      bool
		wantOrigin string
	}{
		{"production", "telecrypt.io", true, "https://backend.telecrypt.io"},
		{"stage", "stage.telecrypt.io", true, "https://backend.stage.telecrypt.io"},
		{"nested hostname", "foo.stage.telecrypt.io", false, "SERVER_NAME"},
		{"wrong suffix", "stage.example.com", false, "SERVER_NAME"},
		{"uppercase label", "Stage.telecrypt.io", false, "SERVER_NAME"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoints, err := deriveBackendEndpoints(tt.serverName)
			if tt.valid {
				if err != nil {
					t.Fatalf("deriveBackendEndpoints: %v", err)
				}
				if endpoints.origin != tt.wantOrigin {
					t.Fatalf("backend = %q, want %q", endpoints.origin, tt.wantOrigin)
				}
				if endpoints.mas != endpoints.origin+"/auth" || endpoints.plan != endpoints.origin+"/plan" {
					t.Fatalf("derived endpoints = %#v", endpoints)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantOrigin) {
				t.Fatalf("error = %v, want %q", err, tt.wantOrigin)
			}
		})
	}
}

func TestServerIdentityDerivedLabelLengthBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		label string
		valid bool
	}{
		{name: "maximum", label: strings.Repeat("a", maxDerivedServerLabelBytes), valid: true},
		{name: "one over maximum", label: strings.Repeat("a", maxDerivedServerLabelBytes+1), valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := deriveBackendEndpoints(tc.label + ".telecrypt.io")
			if (err == nil) != tc.valid {
				t.Fatalf("deriveBackendEndpoints(%q) error = %v, valid = %t", tc.label, err, tc.valid)
			}
		})
	}
}

func TestLoadJanitorUsesExactDatabaseIdentity(t *testing.T) {
	setRequiredJanitorEnv(t)
	cfg, err := LoadJanitor()
	if err != nil {
		t.Fatalf("LoadJanitor: %v", err)
	}
	if got, want := cfg.MASAdminURL, "http://mas-admin:8081"; got != want {
		t.Fatalf("MASAdminURL = %q, want %q", got, want)
	}
	if got, want := cfg.CashierDBRole, "telecrypt_cashier_stage_user"; got != want {
		t.Fatalf("CashierDBRole = %q, want %q", got, want)
	}

	t.Setenv("JANITOR_DB_URL", "postgres://wrong_user:secret@db/telecrypt_billing_stage")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "JANITOR_DB_URL") {
		t.Fatalf("LoadJanitor error = %v, want identity error", err)
	}
	t.Setenv("JANITOR_DB_URL", "postgres://telecrypt_janitor_stage:secret@db/wrong_database")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "JANITOR_DB_URL") {
		t.Fatalf("LoadJanitor error = %v, want database error", err)
	}
}

func TestLoadJanitorRequiresCompleteSMTPUnlessDryRun(t *testing.T) {
	for _, name := range []string{"SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"} {
		t.Run(name, func(t *testing.T) {
			setLiveJanitorEnv(t)
			t.Setenv(name, "")
			_, err := LoadJanitor()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadJanitor error = %v, want missing %s", err, name)
			}
			if strings.Contains(err.Error(), "smtp-secret") {
				t.Fatalf("LoadJanitor error revealed an SMTP secret: %v", err)
			}
		})
	}

	setRequiredJanitorEnv(t)
	for _, name := range []string{"SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"} {
		t.Setenv(name, "")
	}
	t.Setenv("JANITOR_DRY_RUN", "1")
	cfg, err := LoadJanitor()
	if err != nil {
		t.Fatalf("LoadJanitor dry run without SMTP: %v", err)
	}
	if !cfg.DryRun {
		t.Fatal("LoadJanitor dry-run configuration did not set DryRun")
	}

	setLiveJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "OWNER_EMAIL") {
		t.Fatalf("LoadJanitor error = %v, want missing OWNER_EMAIL", err)
	}

	setLiveJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "not-an-email")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "OWNER_EMAIL") {
		t.Fatalf("LoadJanitor error = %v, want invalid OWNER_EMAIL", err)
	}

	setRequiredJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "")
	t.Setenv("JANITOR_DRY_RUN", "1")
	if _, err := LoadJanitor(); err != nil {
		t.Fatalf("LoadJanitor dry run without OWNER_EMAIL: %v", err)
	}
}

func TestLoadJanitorRejectsInvalidDryRunValues(t *testing.T) {
	for _, value := range []string{"", "2", "true", "01", " 1"} {
		t.Run(value, func(t *testing.T) {
			setRequiredJanitorEnv(t)
			t.Setenv("JANITOR_DRY_RUN", value)
			if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "JANITOR_DRY_RUN") {
				t.Fatalf("LoadJanitor error = %v, want JANITOR_DRY_RUN validation error", err)
			}
		})
	}
}

func TestLoadJanitorRequiresDryRunKeyPresence(t *testing.T) {
	setRequiredJanitorEnv(t)
	if err := os.Unsetenv("JANITOR_DRY_RUN"); err != nil {
		t.Fatalf("unset JANITOR_DRY_RUN: %v", err)
	}
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "explicitly set") {
		t.Fatalf("LoadJanitor error = %v, want missing JANITOR_DRY_RUN rejection", err)
	}
}

func TestLoadJanitorRequiresCanonicalMASClientULID(t *testing.T) {
	for _, value := range []string{"janitor", "81J00000000000000000000000", "01j00000000000000000000000", "01J0000000000000000000000O"} {
		t.Run(value, func(t *testing.T) {
			setRequiredJanitorEnv(t)
			t.Setenv("MAS_ADMIN_CLIENT_ID", value)
			if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "MAS_ADMIN_CLIENT_ID") {
				t.Fatalf("LoadJanitor error = %v, want canonical MAS client ULID rejection", err)
			}
		})
	}
}

func TestLoadJanitorRejectsSurroundingWhitespaceInConfiguration(t *testing.T) {
	for _, name := range []string{"MAS_ADMIN_CLIENT_ID", "MAS_ADMIN_CLIENT_SECRET", "SMTP_PASSWORD"} {
		t.Run(name, func(t *testing.T) {
			setRequiredJanitorEnv(t)
			t.Setenv(name, " secret ")
			if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadJanitor error = %v, want %s whitespace rejection", err, name)
			}
		})
	}
}

func TestLoadJanitorParsesAndNormalizesDeliveryMailboxes(t *testing.T) {
	setLiveJanitorEnv(t)
	t.Setenv("OWNER_EMAIL", "Owner <owner@example.test>")
	t.Setenv("SMTP_FROM", "TeleCrypt <noreply@example.test>")
	cfg, err := LoadJanitor()
	if err != nil {
		t.Fatalf("LoadJanitor: %v", err)
	}
	if cfg.OwnerEmail != "owner@example.test" || cfg.SMTPFrom != "noreply@example.test" {
		t.Fatalf("mailboxes = (%q, %q), want bare parsed addresses", cfg.OwnerEmail, cfg.SMTPFrom)
	}
}

func TestLoadJanitorRejectsInvalidSMTPFrom(t *testing.T) {
	setLiveJanitorEnv(t)
	t.Setenv("SMTP_FROM", "not-an-email")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "SMTP_FROM") {
		t.Fatalf("LoadJanitor error = %v, want invalid SMTP_FROM rejection", err)
	}
}

func TestLoadJanitorRejectsUnsupportedServerProfile(t *testing.T) {
	setRequiredJanitorEnv(t)
	t.Setenv("SERVER_NAME", "preview.telecrypt.io")
	t.Setenv("BILLING_ENVIRONMENT", "test")
	if _, err := LoadJanitor(); err == nil {
		t.Fatal("LoadJanitor accepted an unsupported billing profile")
	}
}

func TestLoadJanitorUsesProductionDatabaseIdentity(t *testing.T) {
	setLiveJanitorEnv(t)
	t.Setenv("SERVER_NAME", "telecrypt.io")
	t.Setenv("BILLING_ENVIRONMENT", "live")
	t.Setenv("JANITOR_DRY_RUN", "0")
	t.Setenv("JANITOR_DB_URL", "postgres://telecrypt_janitor_user:secret@db/telecrypt_billing")
	if _, err := LoadJanitor(); err != nil {
		t.Fatalf("LoadJanitor in production: %v", err)
	}
}

func TestLoadJanitorRejectsProductionDryRunBeforeMailConfiguration(t *testing.T) {
	setRequiredJanitorEnv(t)
	t.Setenv("SERVER_NAME", "telecrypt.io")
	t.Setenv("BILLING_ENVIRONMENT", "live")
	t.Setenv("JANITOR_DB_URL", "postgres://telecrypt_janitor_user:secret@db/telecrypt_billing")
	t.Setenv("JANITOR_DRY_RUN", "1")
	for _, name := range []string{"OWNER_EMAIL", "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"} {
		t.Setenv(name, "")
	}

	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "JANITOR_DRY_RUN") {
		t.Fatalf("LoadJanitor error = %v, want production JANITOR_DRY_RUN rejection", err)
	}
}

func TestLoadJanitorRejectsInvalidDatabaseURL(t *testing.T) {
	setRequiredJanitorEnv(t)
	t.Setenv("JANITOR_DB_URL", "https://db.invalid")
	if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "JANITOR_DB_URL") {
		t.Fatalf("LoadJanitor error = %v, want explicit Postgres URL error", err)
	}
}

func TestLoadAndValidateRegistrationDerivesPublicURLs(t *testing.T) {
	t.Setenv("SERVER_NAME", "telecrypt.io")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.BackendPublicURL, "https://backend.telecrypt.io"; got != want {
		t.Fatalf("BackendPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.MASPublicURL, "https://backend.telecrypt.io/auth"; got != want {
		t.Fatalf("MASPublicURL = %q, want %q", got, want)
	}
	if got, want := cfg.PlanPublicURL, "https://backend.telecrypt.io/plan"; got != want {
		t.Fatalf("PlanPublicURL = %q, want %q", got, want)
	}
	if err := cfg.ValidateRegistration(); err != nil {
		t.Fatalf("ValidateRegistration rejected a valid configuration: %v", err)
	}
	cfg.MASPublicURL = "http://mas:8080"
	if err := cfg.ValidateRegistration(); err == nil {
		t.Fatal("ValidateRegistration accepted an internal MAS endpoint")
	}
}

func TestLoadJanitorRejectsUnsafeDatabaseQuery(t *testing.T) {
	base := "postgres://telecrypt_janitor_stage_user:secret@db/telecrypt_billing_stage"
	for _, query := range []string{
		"host=other.example",
		"hostaddr=127.0.0.1",
		"port=6543",
		"user=other_user",
		"database=other_db",
		"dbname=other_db",
		"service=other_service",
		"host=first&host=second",
		"%68ost=other.example",
		"%68%6f%73%74=other.example",
		"HOST=other.example",
		"servicefile=/tmp/service.conf",
		"passfile=/tmp/passfile",
		"sslkey=/tmp/client.key",
		"sslcert=/tmp/client.crt",
		"sslrootcert=/tmp/root.crt",
		"options=-c%20search_path%3Dpublic",
		"search_path=public",
		"unknown=value",
		"sslmode=require&sslmode=disable",
		"%73slmode=require",
		"sslmode=",
		"sslmode=%20",
		"sslmode=require&",
		"sslmode=require&application_name=%20janitor",
	} {
		t.Run(query, func(t *testing.T) {
			setRequiredJanitorEnv(t)
			t.Setenv("JANITOR_DB_URL", base+"?"+query)
			if _, err := LoadJanitor(); err == nil || !strings.Contains(err.Error(), "query") {
				t.Fatalf("LoadJanitor error = %v, want query-target rejection", err)
			}
		})
	}
}

func TestLoadJanitorAllowsSafeDatabaseConnectionOptions(t *testing.T) {
	setRequiredJanitorEnv(t)
	t.Setenv("JANITOR_DB_URL", "postgres://telecrypt_janitor_stage_user:secret@db/telecrypt_billing_stage?sslmode=require&connect_timeout=5&application_name=janitor-sweep")
	if _, err := LoadJanitor(); err != nil {
		t.Fatalf("LoadJanitor rejected safe query options: %v", err)
	}
}
