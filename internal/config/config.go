// Package config loads each public control-plane binary configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config is redpill configuration.
type Config struct {
	LogLevel           string
	ListenAddr         string
	MASBaseURL         string
	Homeserver         string
	PlanURL            string
	ServerName         string
	RateLimitPerSource int
	RateLimitGlobal    int
	RateLimitWindowSec int
	IgnoredProxyIP     string
}

func Load() (*Config, error) {
	return &Config{
		LogLevel:           getenvDefault("LOG_LEVEL", "info"),
		ListenAddr:         getenvDefault("LISTEN_ADDR", ":9009"),
		MASBaseURL:         getenvDefault("MAS_BASE_URL", "https://backend.telecrypt.io/auth"),
		Homeserver:         getenvDefault("HOMESERVER", "https://backend.telecrypt.io"),
		PlanURL:            getenvDefault("PLAN_URL", "https://backend.telecrypt.io/plan"),
		ServerName:         getenvDefault("SERVER_NAME", ""),
		RateLimitPerSource: getenvIntDefault("RATE_LIMIT_PER_SOURCE", 5),
		RateLimitGlobal:    getenvIntDefault("RATE_LIMIT_GLOBAL", 60),
		RateLimitWindowSec: getenvIntDefault("RATE_LIMIT_WINDOW_SEC", 60),
		IgnoredProxyIP:     strings.TrimSpace(os.Getenv("IGNORED_PROXY_IP")),
	}, nil
}

// ValidateRedpill rejects a configuration that would weaken Redpill's public OAuth boundary or
// make the in-process backstop unavailable. Redpill has no internal MAS credential, so its MAS,
// homeserver, and Plan URLs must all be browser-visible HTTPS endpoints.
func (c *Config) ValidateRedpill() error {
	for _, endpoint := range []struct {
		name string
		url  string
	}{
		{"MAS_BASE_URL", c.MASBaseURL},
		{"HOMESERVER", c.Homeserver},
		{"PLAN_URL", c.PlanURL},
	} {
		if err := validatePublicHTTPSURL(endpoint.url, endpoint.name); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.ServerName) == "" {
		return fmt.Errorf("SERVER_NAME must not be empty")
	}
	if c.RateLimitPerSource <= 0 || c.RateLimitGlobal <= 0 || c.RateLimitWindowSec <= 0 {
		return fmt.Errorf("Redpill rate limits and window must all be positive")
	}
	return nil
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getenvBool(key string) bool { return os.Getenv(key) == "1" }

func getenvList(key string) []string {
	var out []string
	for _, value := range strings.Split(os.Getenv(key), ",") {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

// LockerConfig is Janitor configuration. Cashier alone writes payment state; Janitor verifies
// its explicit environment guard before it reads the Cashier-owned entitlement grants.
type LockerConfig struct {
	LogLevel             string
	BillingEnv           string
	MatrixDeployment     string
	RunOnce              bool
	DryRun               bool
	SweepIntervalSec     int
	MASBaseURL           string
	MASAdminClientID     string
	MASAdminClientSecret string
	ControlplaneDBURL    string
	ServerName           string
	LockAfterHours       int
	ExcludeMXIDs         map[string]bool
	OwnerEmail           string
	SMTPHost             string
	SMTPPort             string
	SMTPUsername         string
	SMTPPassword         string
	SMTPFrom             string
}

func LoadLocker() (*LockerConfig, error) {
	exclude := make(map[string]bool)
	for _, mxid := range getenvList("EXCLUDE_MXIDS") {
		exclude[mxid] = true
	}
	c := &LockerConfig{
		LogLevel:             getenvDefault("LOG_LEVEL", "info"),
		BillingEnv:           os.Getenv("BILLING_ENV"),
		MatrixDeployment:     os.Getenv("MATRIX_DEPLOYMENT_ID"),
		RunOnce:              getenvBool("RUN_ONCE"),
		DryRun:               getenvBool("DRY_RUN"),
		SweepIntervalSec:     getenvIntDefault("SWEEP_INTERVAL_SEC", 3600),
		MASBaseURL:           os.Getenv("MAS_BASE_URL"),
		MASAdminClientID:     os.Getenv("MAS_ADMIN_CLIENT_ID"),
		MASAdminClientSecret: os.Getenv("MAS_ADMIN_CLIENT_SECRET"),
		ControlplaneDBURL:    os.Getenv("CONTROLPLANE_DB_URL"),
		ServerName:           os.Getenv("SERVER_NAME"),
		LockAfterHours:       getenvIntDefault("LOCK_AFTER_HOURS", 48),
		ExcludeMXIDs:         exclude,
		OwnerEmail:           os.Getenv("OWNER_EMAIL"),
		SMTPHost:             os.Getenv("SMTP_HOST"),
		SMTPPort:             getenvDefault("SMTP_PORT", "587"),
		SMTPUsername:         os.Getenv("SMTP_USERNAME"),
		SMTPPassword:         os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:             os.Getenv("SMTP_FROM"),
	}
	var missing []string
	for _, req := range []struct{ name, value string }{
		{"BILLING_ENV", c.BillingEnv}, {"MATRIX_DEPLOYMENT_ID", c.MatrixDeployment},
		{"MAS_BASE_URL", c.MASBaseURL}, {"MAS_ADMIN_CLIENT_ID", c.MASAdminClientID},
		{"MAS_ADMIN_CLIENT_SECRET", c.MASAdminClientSecret}, {"CONTROLPLANE_DB_URL", c.ControlplaneDBURL},
		{"SERVER_NAME", c.ServerName},
	} {
		if req.value == "" {
			missing = append(missing, req.name)
		}
	}
	if c.SMTPHost != "" && c.SMTPFrom == "" {
		missing = append(missing, "SMTP_FROM (required once SMTP_HOST is set)")
	}
	if len(missing) != 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	if c.BillingEnv != "test" && c.BillingEnv != "production" {
		return nil, fmt.Errorf("BILLING_ENV must be exactly test or production")
	}
	return c, nil
}

// StewardConfig contains the browser-facing service configuration. It has no payment,
// Synapse-admin, or database credentials.
type StewardConfig struct {
	LogLevel                   string
	ListenAddr                 string
	BillingEnv                 string
	ServerName                 string
	Homeserver                 string
	MASBaseURL                 string
	PlanPublicURL              string
	CashierInternalURL         string
	MASClientID                string
	MASClientSecret            string
	SessionKey                 string
	StewardAssertionPrivateKey string
}

func LoadSteward() (*StewardConfig, error) {
	c := &StewardConfig{
		LogLevel:                   getenvDefault("LOG_LEVEL", "info"),
		ListenAddr:                 getenvDefault("LISTEN_ADDR", ":9012"),
		BillingEnv:                 os.Getenv("BILLING_ENV"),
		ServerName:                 os.Getenv("SERVER_NAME"),
		Homeserver:                 getenvDefault("HOMESERVER", "https://backend.telecrypt.io"),
		MASBaseURL:                 os.Getenv("MAS_BASE_URL"),
		PlanPublicURL:              getenvDefault("PLAN_PUBLIC_URL", "https://backend.telecrypt.io/plan"),
		CashierInternalURL:         getenvDefault("CASHIER_INTERNAL_URL", "http://cashier:9011"),
		MASClientID:                os.Getenv("MAS_OIDC_CLIENT_ID"),
		MASClientSecret:            os.Getenv("MAS_OIDC_CLIENT_SECRET"),
		SessionKey:                 os.Getenv("SESSION_KEY"),
		StewardAssertionPrivateKey: os.Getenv("STEWARD_ASSERTION_PRIVATE_KEY"),
	}
	for _, req := range []struct{ name, value string }{
		{"SERVER_NAME", c.ServerName}, {"BILLING_ENV", c.BillingEnv}, {"MAS_BASE_URL", c.MASBaseURL},
		{"MAS_OIDC_CLIENT_ID", c.MASClientID}, {"MAS_OIDC_CLIENT_SECRET", c.MASClientSecret},
		{"SESSION_KEY", c.SessionKey}, {"STEWARD_ASSERTION_PRIVATE_KEY", c.StewardAssertionPrivateKey},
	} {
		if req.value == "" {
			return nil, fmt.Errorf("missing required env var: %s", req.name)
		}
	}
	if c.BillingEnv != "test" && c.BillingEnv != "production" {
		return nil, fmt.Errorf("BILLING_ENV must be exactly test or production")
	}
	if len(c.SessionKey) < 32 {
		return nil, fmt.Errorf("SESSION_KEY must contain at least 32 bytes")
	}
	if err := validatePublicHTTPSURL(c.Homeserver, "HOMESERVER"); err != nil {
		return nil, err
	}
	if err := validatePublicHTTPSURL(c.PlanPublicURL, "PLAN_PUBLIC_URL"); err != nil {
		return nil, err
	}
	if err := validateComposeInternalOrigin(c.CashierInternalURL, "cashier", "9011", "CASHIER_INTERNAL_URL"); err != nil {
		return nil, err
	}
	if err := validateComposeInternalOrigin(c.MASBaseURL, "mas", "8080", "MAS_BASE_URL"); err != nil {
		return nil, err
	}
	return c, nil
}

func validatePublicHTTPSURL(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be a public HTTPS URL", name)
	}
	return nil
}

func validateComposeInternalOrigin(raw, host, port, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() != host || u.Port() != port || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be the Compose-local origin http://%s:%s", name, host, port)
	}
	return nil
}
