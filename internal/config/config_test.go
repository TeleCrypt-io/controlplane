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
		"CONTROLPLANE_DB_URL":    "postgres://cashier@db.test/telecrypt_test",
		"HOMESERVER":             "https://backend.test.telecrypt.io",
		"PLAN_PUBLIC_URL":        "https://backend.test.telecrypt.io/plan",
		"DODO_API_KEY":           "test-key",
		"DODO_WEBHOOK_SECRET":    "test-webhook",
		"DODO_PRODUCT_ID":        "prod_test",
		"BILLING_ENV":            "test",
		"MATRIX_DEPLOYMENT_ID":   "billing-test",
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

func TestLoadCashier_AllowsExplicitComposeSynapseAdminURL(t *testing.T) {
	setRequiredCashierEnv(t)
	t.Setenv("SYNAPSE_ADMIN_URL", "http://synapse:8008/")

	cfg, err := LoadCashier()
	if err != nil {
		t.Fatalf("LoadCashier: %v", err)
	}
	if got, want := cfg.SynapseAdminURL, "http://synapse:8008/"; got != want {
		t.Fatalf("SynapseAdminURL = %q, want %q", got, want)
	}
}

func TestLoadCashier_RequiresExplicitCompatibleBillingEnvironment(t *testing.T) {
	tests := []struct {
		name, env, base, want string
	}{
		{"missing environment", "", "https://test.dodopayments.com", "BILLING_ENV"},
		{"unknown environment", "staging", "https://test.dodopayments.com", "BILLING_ENV"},
		{"test uses live API", "test", "https://live.dodopayments.com", "incompatible"},
		{"production uses test API", "production", "https://test.dodopayments.com", "incompatible"},
		{"non HTTPS API", "test", "http://test.dodopayments.com", "HTTPS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredCashierEnv(t)
			t.Setenv("BILLING_ENV", tt.env)
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
	t.Setenv("BILLING_ENV", "production")
	t.Setenv("MATRIX_DEPLOYMENT_ID", "production")
	t.Setenv("DODO_API_BASE", "https://live.dodopayments.com")
	t.Setenv("SERVER_NAME", "telecrypt.io")
	t.Setenv("HOMESERVER", "https://backend.telecrypt.io")
	t.Setenv("PLAN_PUBLIC_URL", "https://backend.telecrypt.io/plan")
	t.Setenv("CONTROLPLANE_DB_URL", "postgres://cashier@db/telecrypt")
	if _, err := LoadCashier(); err != nil {
		t.Fatalf("LoadCashier production: %v", err)
	}
}

func TestLoadCashier_TestBillingCanUseProductionMatrixWithExplicitIdentities(t *testing.T) {
	setRequiredCashierEnv(t)
	t.Setenv("MATRIX_DEPLOYMENT_ID", "production")
	t.Setenv("SERVER_NAME", "telecrypt.io")
	t.Setenv("HOMESERVER", "https://backend.telecrypt.io")
	t.Setenv("PLAN_PUBLIC_URL", "https://backend.telecrypt.io/plan")
	t.Setenv("CONTROLPLANE_DB_URL", "postgres://cashier@db/telecrypt")
	if _, err := LoadCashier(); err != nil {
		t.Fatalf("LoadCashier production Matrix with test billing: %v", err)
	}
}

func TestLoadCashier_ProductionMatrixRequiresExactPublicOrigins(t *testing.T) {
	setRequiredCashierEnv(t)
	t.Setenv("MATRIX_DEPLOYMENT_ID", "production")
	t.Setenv("SERVER_NAME", "telecrypt.io")
	t.Setenv("HOMESERVER", "https://wrong.telecrypt.io")
	t.Setenv("PLAN_PUBLIC_URL", "https://backend.telecrypt.io/plan")
	if _, err := LoadCashier(); err == nil || !strings.Contains(err.Error(), "MATRIX_DEPLOYMENT_ID") {
		t.Fatalf("LoadCashier error = %v, want exact production origin error", err)
	}
}

func TestLoadCashier_ProductionRejectsTestIdentifiers(t *testing.T) {
	tests := []struct {
		name, planURL, databaseURL string
	}{
		{"production Plan on test host", "https://billing-test.telecrypt.io/plan", "postgres://cashier@db/telecrypt"},
		{"production service on test database", "https://billing.telecrypt.io/plan", "postgres://cashier@db.test/telecrypt_test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredCashierEnv(t)
			t.Setenv("BILLING_ENV", "production")
			t.Setenv("PLAN_PUBLIC_URL", tt.planURL)
			t.Setenv("CONTROLPLANE_DB_URL", tt.databaseURL)
			t.Setenv("DODO_API_BASE", "https://live.dodopayments.com")
			t.Setenv("MATRIX_DEPLOYMENT_ID", "production")
			t.Setenv("SERVER_NAME", "telecrypt.io")
			t.Setenv("HOMESERVER", "https://backend.telecrypt.io")
			if _, err := LoadCashier(); err == nil {
				t.Fatalf("LoadCashier error = %v, want environment boundary error", err)
			}
		})
	}
}

func TestLoadCashier_RejectsNonLocalEnforcementTargets(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{"external Synapse", "SYNAPSE_ADMIN_URL", "https://backend.telecrypt.io"},
		{"wrong Synapse service", "SYNAPSE_ADMIN_URL", "http://synapse-production:8008"},
		{"external MAS", "MAS_BASE_URL", "https://backend.telecrypt.io/auth"},
		{"wrong MAS service", "MAS_BASE_URL", "http://mas-production:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredCashierEnv(t)
			t.Setenv(tt.key, tt.value)
			if _, err := LoadCashier(); err == nil || !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("LoadCashier error = %v, want %s boundary error", err, tt.key)
			}
		})
	}
}
