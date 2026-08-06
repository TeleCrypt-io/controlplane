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
		"HOMESERVER":                    "https://backend.test.telecrypt.io",
		"MAS_BASE_URL":                  "http://mas:8080",
		"PLAN_PUBLIC_URL":               "https://backend.test.telecrypt.io/plan",
		"CASHIER_INTERNAL_URL":          "http://cashier:9011",
		"MAS_OIDC_CLIENT_ID":            "steward",
		"MAS_OIDC_CLIENT_SECRET":        "test-secret",
		"SESSION_KEY":                   "test-session-key",
		"STEWARD_ASSERTION_PRIVATE_KEY": strings.Repeat("A", 86),
	} {
		t.Setenv(key, value)
	}
}

func TestLoadSteward_UsesPrivateCashierTopology(t *testing.T) {
	setRequiredStewardEnv(t)
	cfg, err := LoadSteward()
	if err != nil {
		t.Fatalf("LoadSteward: %v", err)
	}
	if got, want := cfg.ListenAddr, ":9012"; got != want {
		t.Fatalf("ListenAddr = %q, want %q", got, want)
	}
}

func TestLoadSteward_RejectsPublicCashierOrigin(t *testing.T) {
	setRequiredStewardEnv(t)
	t.Setenv("CASHIER_INTERNAL_URL", "https://billing.test.telecrypt.io")
	if _, err := LoadSteward(); err == nil {
		t.Fatal("LoadSteward accepted public Cashier origin")
	}
}

func TestLoadLocker_RejectsUnknownBillingEnvironment(t *testing.T) {
	for key, value := range map[string]string{
		"BILLING_ENV": "sandbox", "MATRIX_DEPLOYMENT_ID": "test", "MAS_BASE_URL": "http://mas:8080",
		"MAS_ADMIN_CLIENT_ID": "janitor", "MAS_ADMIN_CLIENT_SECRET": "secret",
		"CONTROLPLANE_DB_URL": "postgres://janitor@db/test", "SERVER_NAME": "telecrypt.test",
	} {
		t.Setenv(key, value)
	}
	if _, err := LoadLocker(); err == nil {
		t.Fatal("LoadLocker accepted invalid billing environment")
	}
}

func TestLoadAgentIssuerRequiresPrivateOAuthBoundary(t *testing.T) {
	for key, value := range map[string]string{
		"MAS_BASE_URL": "http://mas:8080", "MAS_ADMIN_CLIENT_ID": "issuer",
		"MAS_ADMIN_CLIENT_SECRET": "secret", "HOMESERVER": "https://backend.test.telecrypt.io",
		"SERVER_NAME": "telecrypt.test", "REDPILL_ASSERTION_PUBLIC_KEY": strings.Repeat("A", 43),
	} {
		t.Setenv(key, value)
	}
	if _, err := LoadAgentIssuer(); err != nil {
		t.Fatalf("LoadAgentIssuer: %v", err)
	}
	t.Setenv("MAS_ADMIN_CLIENT_SECRET", "")
	if _, err := LoadAgentIssuer(); err == nil {
		t.Fatal("LoadAgentIssuer accepted missing MAS admin OAuth secret")
	}
}
