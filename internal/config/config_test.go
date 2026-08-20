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
		"SESSION_KEY":                   strings.Repeat("s", 32),
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

func TestLoadSteward_RejectsShortSessionKey(t *testing.T) {
	setRequiredStewardEnv(t)
	t.Setenv("SESSION_KEY", "too-short")
	if _, err := LoadSteward(); err == nil {
		t.Fatal("LoadSteward accepted a short session signing key")
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

func TestLoad_RejectsMalformedRateLimit(t *testing.T) {
	for _, key := range []string{"RATE_LIMIT_PER_SOURCE", "RATE_LIMIT_GLOBAL", "RATE_LIMIT_WINDOW_SEC"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "not-an-integer")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load error = %v, want malformed %s error", err, key)
			}
		})
	}
}

func TestLoad_DoesNotDefaultPublicEnvironmentURLs(t *testing.T) {
	for _, key := range []string{"MAS_BASE_URL", "HOMESERVER", "PLAN_URL"} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if err := cfg.ValidateRedpill(); err == nil {
		t.Fatal("ValidateRedpill accepted missing environment-specific public URLs")
	}
}

func TestLoadLocker_RejectsMalformedNumericSetting(t *testing.T) {
	for _, key := range []string{"SWEEP_INTERVAL_SEC", "LOCK_AFTER_HOURS", "SMTP_TIMEOUT_SEC"} {
		t.Run(key, func(t *testing.T) {
			for envKey, value := range map[string]string{
				"BILLING_ENV": "test", "MATRIX_DEPLOYMENT_ID": "test", "MAS_BASE_URL": "http://mas:8080",
				"MAS_ADMIN_CLIENT_ID": "janitor", "MAS_ADMIN_CLIENT_SECRET": "secret",
				"CONTROLPLANE_DB_URL": "postgres://janitor@db/test", "SERVER_NAME": "telecrypt.test",
			} {
				t.Setenv(envKey, value)
			}
			t.Setenv(key, "not-an-integer")
			if _, err := LoadLocker(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("LoadLocker error = %v, want malformed %s error", err, key)
			}
		})
	}
}

func TestValidateRedpill_RequiresPublicEndpointsAndPositiveLimits(t *testing.T) {
	cfg := &Config{
		MASBaseURL:         "https://backend.telecrypt.io/auth",
		Homeserver:         "https://backend.telecrypt.io",
		PlanURL:            "https://backend.telecrypt.io/plan",
		ServerName:         "telecrypt.io",
		RateLimitPerSource: 5,
		RateLimitGlobal:    60,
		RateLimitWindowSec: 60,
	}
	if err := cfg.ValidateRedpill(); err != nil {
		t.Fatalf("ValidateRedpill rejected a valid configuration: %v", err)
	}

	cfg.MASBaseURL = "http://mas:8080"
	if err := cfg.ValidateRedpill(); err == nil {
		t.Fatal("ValidateRedpill accepted an internal MAS endpoint")
	}
	cfg.MASBaseURL = "https://backend.telecrypt.io/auth"
	cfg.RateLimitWindowSec = 0
	if err := cfg.ValidateRedpill(); err == nil {
		t.Fatal("ValidateRedpill accepted a non-positive rate-limit window")
	}
}
