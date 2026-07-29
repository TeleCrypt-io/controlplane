package config

import (
	"strings"
	"testing"
)

func setRequiredCashierEnv(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SERVER_NAME":            "telecrypt.test",
		"MAS_BASE_URL":           "http://mas:8080",
		"SYNAPSE_ADMIN_TOKEN":    "test-token",
		"MAS_OIDC_CLIENT_ID":     "cashier",
		"MAS_OIDC_CLIENT_SECRET": "test-secret",
		"SESSION_KEY":            "test-session-key",
		"CONTROLPLANE_DB_URL":    "postgres://test",
		"DODO_API_KEY":           "test-key",
		"DODO_WEBHOOK_SECRET":    "test-webhook",
		"DODO_PRODUCT_ID":        "prod_test",
		"TELECRYPT_ENV":          "test",
		"DODO_API_BASE":          "https://test.dodopayments.com",
	} {
		t.Setenv(key, value)
	}
}

func TestLoadCashier_UsesInternalSynapseAdminURLByDefault(t *testing.T) {
	setRequiredCashierEnv(t)
	t.Setenv("SYNAPSE_ADMIN_URL", "")

	cfg, err := LoadCashier()
	if err != nil {
		t.Fatalf("LoadCashier: %v", err)
	}
	if got, want := cfg.SynapseAdminURL, "http://synapse:8008"; got != want {
		t.Fatalf("SynapseAdminURL = %q, want %q", got, want)
	}
}

func TestLoadCashier_AllowsExplicitSynapseAdminURL(t *testing.T) {
	setRequiredCashierEnv(t)
	t.Setenv("SYNAPSE_ADMIN_URL", "http://synapse.internal:8008")

	cfg, err := LoadCashier()
	if err != nil {
		t.Fatalf("LoadCashier: %v", err)
	}
	if got, want := cfg.SynapseAdminURL, "http://synapse.internal:8008"; got != want {
		t.Fatalf("SynapseAdminURL = %q, want %q", got, want)
	}
}

func TestLoadCashier_RequiresExplicitCompatibleBillingEnvironment(t *testing.T) {
	tests := []struct {
		name, env, base, want string
	}{
		{"missing environment", "", "https://test.dodopayments.com", "TELECRYPT_ENV"},
		{"unknown environment", "staging", "https://test.dodopayments.com", "TELECRYPT_ENV"},
		{"test uses live API", "test", "https://live.dodopayments.com", "incompatible"},
		{"production uses test API", "production", "https://test.dodopayments.com", "incompatible"},
		{"non HTTPS API", "test", "http://test.dodopayments.com", "HTTPS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredCashierEnv(t)
			t.Setenv("TELECRYPT_ENV", tt.env)
			t.Setenv("DODO_API_BASE", tt.base)
			_, err := LoadCashier()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadCashier error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadCashier_ProductionUsesLiveDodoAPI(t *testing.T) {
	setRequiredCashierEnv(t)
	t.Setenv("TELECRYPT_ENV", "production")
	t.Setenv("DODO_API_BASE", "https://live.dodopayments.com")
	if _, err := LoadCashier(); err != nil {
		t.Fatalf("LoadCashier production: %v", err)
	}
}
