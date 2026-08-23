// Package config loads each public control-plane binary configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config is redpill configuration.
type Config struct {
	BackendPublicURL string
	MASPublicURL     string
	PlanPublicURL    string
	ServerName       string
}

func Load() (*Config, error) {
	backend, err := deriveBackendEndpoints(os.Getenv("BACKEND_PUBLIC_URL"))
	if err != nil {
		return nil, err
	}
	return &Config{
		BackendPublicURL: backend.origin,
		MASPublicURL:     backend.mas,
		PlanPublicURL:    backend.plan,
		ServerName:       os.Getenv("SERVER_NAME"),
	}, nil
}

// ValidateRedpill rejects a configuration that would weaken Redpill's public OAuth boundary or
// make the in-process backstop unavailable. Redpill has no internal MAS credential, so its MAS,
// homeserver, and Plan URLs must all be browser-visible HTTPS endpoints.
func (c *Config) ValidateRedpill() error {
	backend, err := deriveBackendEndpoints(c.BackendPublicURL)
	if err != nil {
		return err
	}
	if c.MASPublicURL != backend.mas || c.PlanPublicURL != backend.plan {
		return fmt.Errorf("public MAS and Plan URLs must be derived from BACKEND_PUBLIC_URL")
	}
	for _, endpoint := range []struct {
		name string
		url  string
	}{
		{"BACKEND_PUBLIC_URL", c.BackendPublicURL},
		{"derived MAS /auth URL", c.MASPublicURL},
		{"derived Plan /plan URL", c.PlanPublicURL},
	} {
		if err := validatePublicHTTPSURL(endpoint.url, endpoint.name); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.ServerName) == "" {
		return fmt.Errorf("SERVER_NAME must not be empty")
	}
	return nil
}

func getenvBool(key string) bool { return os.Getenv(key) == "1" }

// LockerConfig is Janitor configuration. Cashier alone writes payment state; Janitor verifies
// its explicit environment guard before it reads the Cashier-owned entitlement grants.
type LockerConfig struct {
	BillingEnv           string
	DryRun               bool
	MASAdminURL          string
	MASAdminClientID     string
	MASAdminClientSecret string
	JanitorDBURL         string
	ServerName           string
	OwnerEmail           string
	SMTPHost             string
	SMTPUsername         string
	SMTPPassword         string
	SMTPFrom             string
}

func LoadLocker() (*LockerConfig, error) {
	c := &LockerConfig{
		BillingEnv:           os.Getenv("BILLING_ENV"),
		DryRun:               getenvBool("DRY_RUN"),
		MASAdminURL:          masAdminURL,
		MASAdminClientID:     os.Getenv("MAS_ADMIN_CLIENT_ID"),
		MASAdminClientSecret: os.Getenv("MAS_ADMIN_CLIENT_SECRET"),
		JanitorDBURL:         os.Getenv("JANITOR_DB_URL"),
		ServerName:           os.Getenv("SERVER_NAME"),
		OwnerEmail:           os.Getenv("OWNER_EMAIL"),
		SMTPHost:             os.Getenv("SMTP_HOST"),
		SMTPUsername:         os.Getenv("SMTP_USERNAME"),
		SMTPPassword:         os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:             os.Getenv("SMTP_FROM"),
	}
	var missing []string
	for _, req := range []struct{ name, value string }{
		{"BILLING_ENV", c.BillingEnv}, {"MAS_ADMIN_CLIENT_ID", c.MASAdminClientID},
		{"MAS_ADMIN_CLIENT_SECRET", c.MASAdminClientSecret}, {"JANITOR_DB_URL", c.JanitorDBURL},
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
	dbURL, err := url.Parse(c.JanitorDBURL)
	if err != nil || (dbURL.Scheme != "postgres" && dbURL.Scheme != "postgresql") || dbURL.Host == "" {
		return nil, fmt.Errorf("JANITOR_DB_URL must be an explicit Postgres URL")
	}
	return c, nil
}

// StewardConfig contains the browser-facing service configuration. It has no payment,
// Synapse-admin, or database credentials.
type StewardConfig struct {
	BillingEnv                 string
	ServerName                 string
	BackendPublicURL           string
	MASInternalURL             string
	PlanPublicURL              string
	CashierInternalURL         string // fixed Compose-local endpoint
	MASClientID                string
	MASClientSecret            string
	SessionKey                 string
	StewardAssertionPrivateKey string
}

func LoadSteward() (*StewardConfig, error) {
	c := &StewardConfig{
		BillingEnv:                 os.Getenv("BILLING_ENV"),
		ServerName:                 os.Getenv("SERVER_NAME"),
		BackendPublicURL:           os.Getenv("BACKEND_PUBLIC_URL"),
		MASInternalURL:             masInternalURL,
		CashierInternalURL:         cashierInternalURL,
		MASClientID:                os.Getenv("MAS_OIDC_CLIENT_ID"),
		MASClientSecret:            os.Getenv("MAS_OIDC_CLIENT_SECRET"),
		SessionKey:                 os.Getenv("SESSION_KEY"),
		StewardAssertionPrivateKey: os.Getenv("STEWARD_ASSERTION_PRIVATE_KEY"),
	}
	for _, req := range []struct{ name, value string }{
		{"SERVER_NAME", c.ServerName}, {"BILLING_ENV", c.BillingEnv}, {"BACKEND_PUBLIC_URL", c.BackendPublicURL},
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
	backend, err := deriveBackendEndpoints(c.BackendPublicURL)
	if err != nil {
		return nil, err
	}
	c.BackendPublicURL = backend.origin
	c.PlanPublicURL = backend.plan
	if err := validatePublicHTTPSURL(c.BackendPublicURL, "BACKEND_PUBLIC_URL"); err != nil {
		return nil, err
	}
	return c, nil
}

const (
	masAdminURL        = "http://mas:8081"
	masInternalURL     = "http://mas:8080"
	cashierInternalURL = "http://cashier:9011"
)

type backendEndpoints struct {
	origin string
	mas    string
	plan   string
}

func deriveBackendEndpoints(raw string) (backendEndpoints, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return backendEndpoints{}, fmt.Errorf("BACKEND_PUBLIC_URL must be an HTTPS origin")
	}
	u.Path, u.RawPath = "", ""
	origin := strings.TrimRight(u.String(), "/")
	return backendEndpoints{origin: origin, mas: origin + "/auth", plan: origin + "/plan"}, nil
}

func validatePublicHTTPSURL(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be a public HTTPS URL", name)
	}
	return nil
}
