// Package config loads redpill's, janitor's, and cashier's environment-variable configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	LogLevel   string // "debug", "info" (default), "warn", or "error"
	ListenAddr string

	MASBaseURL string // MAS PUBLIC base incl. path prefix, e.g. https://backend.telecrypt.io/auth (MAS's registration redirects are built from its public base; the internal mas:8080 404s mid-flow)
	Homeserver string // public base URL, e.g. https://backend.telecrypt.io — compat login endpoint
	PlanURL    string // public Plan page URL returned in /redpill response, e.g. https://backend.telecrypt.io/plan
	ServerName string // MXID server name (domain), e.g. telecrypt.io — when empty, derived from Homeserver host (backward compat)

	// In-memory rate limiting (internal/redpillhttp.RateLimiter) — env-overridable so prod values
	// and a verification run (which legitimately needs many calls from one source in a short
	// window) don't have to share one hardcoded number.
	RateLimitPerSource int
	RateLimitGlobal    int
	RateLimitWindowSec int
	IgnoredProxyIP     string // optional X-Forwarded-For value that carries no client signal
}

func Load() (*Config, error) {
	c := &Config{
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
	}

	return c, nil
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

// getenvBool follows the task's "FOO=1" convention (RUN_ONCE, DRY_RUN) rather than strconv.ParseBool's
// broader true/1/t/... set — any other value, including unset, is false.
func getenvBool(key string) bool {
	return os.Getenv(key) == "1"
}

// getenvList splits a comma-separated env var (e.g. EXCLUDE_MXIDS), trimming whitespace and
// dropping empty entries. Returns nil (not an error) if the var is unset or empty.
func getenvList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// LockerConfig is janitor's environment-variable configuration. Kept separate from
// Config/Load (redpill's) so redpill's env footprint doesn't grow to include locker-only
// variables, and vice versa — the two binaries are deployed independently and each should fail
// closed only on the env vars it actually uses.
type LockerConfig struct {
	LogLevel string // "debug", "info" (default), "warn", or "error"

	BillingEnv       string // explicit Dodo/data environment: test or production
	MatrixDeployment string // explicit Matrix/MAS/Synapse deployment identity

	RunOnce          bool // RUN_ONCE=1: run a single sweep and exit (cron/ops/testing)
	DryRun           bool // DRY_RUN=1: log every action that would be taken, take none
	SweepIntervalSec int  // ticker period when not RUN_ONCE; default 3600

	MASBaseURL           string // required — e.g. http://mas:8080, internal, no /auth prefix
	MASAdminClientID     string // required — client_credentials client_id, scope urn:mas:admin
	MASAdminClientSecret string // required

	ControlplaneDBURL string // required — CONTROLPLANE_DB_URL
	ServerName        string // required — e.g. telecrypt.io, used to derive @username:ServerName

	LockAfterHours int             // default 48
	ExcludeMXIDs   map[string]bool // EXCLUDE_MXIDS, comma-separated — belt-and-suspenders exclusions

	// Owner digest. OWNER_EMAIL is deliberately not required: if unset, the digest half of the
	// sweep is skipped (logged as a warning) but the lock half still runs.
	OwnerEmail   string
	SMTPHost     string
	SMTPPort     string // default "587"
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
}

func LoadLocker() (*LockerConfig, error) {
	exclude := make(map[string]bool)
	for _, mxid := range getenvList("EXCLUDE_MXIDS") {
		exclude[mxid] = true
	}

	c := &LockerConfig{
		LogLevel: getenvDefault("LOG_LEVEL", "info"),

		BillingEnv:       os.Getenv("BILLING_ENV"),
		MatrixDeployment: os.Getenv("MATRIX_DEPLOYMENT_ID"),

		RunOnce:          getenvBool("RUN_ONCE"),
		DryRun:           getenvBool("DRY_RUN"),
		SweepIntervalSec: getenvIntDefault("SWEEP_INTERVAL_SEC", 3600),

		MASBaseURL:           os.Getenv("MAS_BASE_URL"),
		MASAdminClientID:     os.Getenv("MAS_ADMIN_CLIENT_ID"),
		MASAdminClientSecret: os.Getenv("MAS_ADMIN_CLIENT_SECRET"),

		ControlplaneDBURL: os.Getenv("CONTROLPLANE_DB_URL"),
		ServerName:        os.Getenv("SERVER_NAME"),

		LockAfterHours: getenvIntDefault("LOCK_AFTER_HOURS", 48),
		ExcludeMXIDs:   exclude,

		OwnerEmail:   os.Getenv("OWNER_EMAIL"),
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     getenvDefault("SMTP_PORT", "587"),
		SMTPUsername: os.Getenv("SMTP_USERNAME"),
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:     os.Getenv("SMTP_FROM"),
	}

	var missing []string
	for _, req := range []struct{ name, val string }{
		{"BILLING_ENV", c.BillingEnv},
		{"MATRIX_DEPLOYMENT_ID", c.MatrixDeployment},
		{"MAS_BASE_URL", c.MASBaseURL},
		{"MAS_ADMIN_CLIENT_ID", c.MASAdminClientID},
		{"MAS_ADMIN_CLIENT_SECRET", c.MASAdminClientSecret},
		{"CONTROLPLANE_DB_URL", c.ControlplaneDBURL},
		{"SERVER_NAME", c.ServerName},
	} {
		if req.val == "" {
			missing = append(missing, req.name)
		}
	}
	// SMTP_FROM is only required once SMTP_HOST turns the digest into a real send — an empty From
	// header would otherwise go out silently on every email.
	if c.SMTPHost != "" && c.SMTPFrom == "" {
		missing = append(missing, "SMTP_FROM (required once SMTP_HOST is set)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	if c.BillingEnv != "test" && c.BillingEnv != "production" {
		return nil, fmt.Errorf("BILLING_ENV must be exactly test or production")
	}

	return c, nil
}

// CashierConfig is cashier's environment-variable configuration.
type CashierConfig struct {
	LogLevel   string
	ListenAddr string
	// BillingEnv is the explicit billing-provider/data environment, never inferred from a
	// Dodo URL or key. Valid values are "test" and "production". MatrixDeployment separately
	// identifies the Matrix stack, so a production Matrix deployment may deliberately use Dodo's
	// test environment until live billing is enabled.
	BillingEnv       string
	MatrixDeployment string // explicit Matrix/MAS/Synapse + billing dataset identity

	ServerName      string // e.g. telecrypt.io — MXID server name
	Homeserver      string // public base URL for browser-facing MAS OIDC authorization, e.g. https://backend.telecrypt.io
	SynapseAdminURL string // internal Synapse admin API base, e.g. http://synapse:8008
	MASBaseURL      string // internal MAS base for OIDC token/userinfo, e.g. http://mas:8080
	PlanPublicURL   string // public Plan page base, e.g. https://backend.telecrypt.io/plan

	SynapseAdminToken string
	MASClientID       string
	MASClientSecret   string
	SessionKey        string

	ControlplaneDBURL string
	DodoAPIKey        string
	DodoWebhookSecret string
	DodoProductID     string
	DodoAPIBase       string
}

func LoadCashier() (*CashierConfig, error) {
	c := &CashierConfig{
		LogLevel:          getenvDefault("LOG_LEVEL", "info"),
		ListenAddr:        getenvDefault("LISTEN_ADDR", ":9011"),
		BillingEnv:        os.Getenv("BILLING_ENV"),
		MatrixDeployment:  os.Getenv("MATRIX_DEPLOYMENT_ID"),
		ServerName:        os.Getenv("SERVER_NAME"),
		Homeserver:        getenvDefault("HOMESERVER", "https://backend.telecrypt.io"),
		SynapseAdminURL:   getenvDefault("SYNAPSE_ADMIN_URL", "http://synapse:8008"),
		MASBaseURL:        os.Getenv("MAS_BASE_URL"),
		PlanPublicURL:     getenvDefault("PLAN_PUBLIC_URL", "https://backend.telecrypt.io/plan"),
		SynapseAdminToken: os.Getenv("SYNAPSE_ADMIN_TOKEN"),
		MASClientID:       os.Getenv("MAS_OIDC_CLIENT_ID"),
		MASClientSecret:   os.Getenv("MAS_OIDC_CLIENT_SECRET"),
		SessionKey:        os.Getenv("SESSION_KEY"),
		ControlplaneDBURL: os.Getenv("CONTROLPLANE_DB_URL"),
		DodoAPIKey:        os.Getenv("DODO_API_KEY"),
		DodoWebhookSecret: os.Getenv("DODO_WEBHOOK_SECRET"),
		DodoProductID:     os.Getenv("DODO_PRODUCT_ID"),
		DodoAPIBase:       os.Getenv("DODO_API_BASE"),
	}

	var missing []string
	for _, req := range []struct{ name, val string }{
		{"SERVER_NAME", c.ServerName},
		{"MAS_BASE_URL", c.MASBaseURL},
		{"SYNAPSE_ADMIN_TOKEN", c.SynapseAdminToken},
		{"MAS_OIDC_CLIENT_ID", c.MASClientID},
		{"MAS_OIDC_CLIENT_SECRET", c.MASClientSecret},
		{"SESSION_KEY", c.SessionKey},
		{"CONTROLPLANE_DB_URL", c.ControlplaneDBURL},
		{"DODO_API_KEY", c.DodoAPIKey},
		{"DODO_WEBHOOK_SECRET", c.DodoWebhookSecret},
		{"DODO_PRODUCT_ID", c.DodoProductID},
		{"BILLING_ENV", c.BillingEnv},
		{"MATRIX_DEPLOYMENT_ID", c.MatrixDeployment},
		{"DODO_API_BASE", c.DodoAPIBase},
	} {
		if req.val == "" {
			missing = append(missing, req.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	if strings.TrimSpace(c.DodoProductID) == "" {
		return nil, fmt.Errorf("DODO_PRODUCT_ID must not be empty")
	}
	if err := validateCashierEnvironment(c); err != nil {
		return nil, err
	}
	return c, nil
}

// PlanConfig contains only the future public Plan service's own configuration. In particular it
// excludes Dodo, Synapse-admin, and database credentials: Plan will use MAS OIDC and the narrow
// private Cashier API instead.
type PlanConfig struct {
	LogLevel           string
	ListenAddr         string
	PlanPublicURL      string
	CashierInternalURL string
}

// LoadPlan validates the two fixed topology boundaries needed when Plan is activated by a later
// coordinated release. The current Plan command is a fail-closed scaffold and is not deployed.
func LoadPlan() (*PlanConfig, error) {
	c := &PlanConfig{
		LogLevel:           getenvDefault("LOG_LEVEL", "info"),
		ListenAddr:         getenvDefault("LISTEN_ADDR", ":9012"),
		PlanPublicURL:      getenvDefault("PLAN_PUBLIC_URL", "https://backend.telecrypt.io/plan"),
		CashierInternalURL: getenvDefault("CASHIER_INTERNAL_URL", "http://cashier:9011"),
	}
	plan, err := url.Parse(c.PlanPublicURL)
	if err != nil || plan.Scheme != "https" || plan.Host == "" || plan.User != nil || plan.RawQuery != "" || plan.Fragment != "" {
		return nil, fmt.Errorf("PLAN_PUBLIC_URL must be a public HTTPS URL")
	}
	if err := validateComposeInternalOrigin(c.CashierInternalURL, "cashier", "9011", "CASHIER_INTERNAL_URL"); err != nil {
		return nil, err
	}
	return c, nil
}

// validateCashierEnvironment makes the billing environment an explicit, fail-closed choice.
// Do not infer it from an API key: a mixed key/base URL can otherwise charge real customers
// while the service believes it is safely testing (or vice versa).
func validateCashierEnvironment(c *CashierConfig) error {
	if c.BillingEnv != "test" && c.BillingEnv != "production" {
		return fmt.Errorf("BILLING_ENV must be exactly test or production")
	}
	base, err := url.Parse(c.DodoAPIBase)
	if err != nil || base.Scheme != "https" || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return fmt.Errorf("DODO_API_BASE must be an HTTPS Dodo API origin")
	}
	expectedHost := "test.dodopayments.com"
	if c.BillingEnv == "production" {
		expectedHost = "live.dodopayments.com"
	}
	if !strings.EqualFold(base.Host, expectedHost) {
		return fmt.Errorf("DODO_API_BASE %q is incompatible with BILLING_ENV=%s (expected https://%s)", c.DodoAPIBase, c.BillingEnv, expectedHost)
	}
	homeserver, err := url.Parse(c.Homeserver)
	if err != nil || homeserver.Scheme != "https" || homeserver.Host == "" || homeserver.User != nil || homeserver.RawQuery != "" || homeserver.Fragment != "" {
		return fmt.Errorf("HOMESERVER must be a public HTTPS URL")
	}
	plan, err := url.Parse(c.PlanPublicURL)
	if err != nil || plan.Scheme != "https" || plan.Host == "" || plan.User != nil || plan.RawQuery != "" || plan.Fragment != "" {
		return fmt.Errorf("PLAN_PUBLIC_URL must be a public HTTPS URL")
	}
	dbURL, err := url.Parse(c.ControlplaneDBURL)
	if err != nil || (dbURL.Scheme != "postgres" && dbURL.Scheme != "postgresql") || dbURL.Host == "" {
		return fmt.Errorf("CONTROLPLANE_DB_URL must be an explicit Postgres URL")
	}
	planMarkedTest := hasTestEnvironmentMarker(plan.Hostname())
	homeserverMarkedTest := hasTestEnvironmentMarker(homeserver.Hostname())
	serverNameMarkedTest := hasTestEnvironmentMarker(c.ServerName)
	dbMarkedTest := hasTestEnvironmentMarker(dbURL.Hostname()) || hasTestEnvironmentMarker(strings.TrimPrefix(dbURL.Path, "/"))
	if c.MatrixDeployment == "production" {
		if c.ServerName != "telecrypt.io" ||
			!samePublicURL(homeserver, "https://backend.telecrypt.io", "") ||
			!samePublicURL(plan, "https://backend.telecrypt.io", "/plan") {
			return fmt.Errorf("MATRIX_DEPLOYMENT_ID=production requires the exact TeleCrypt production server, Homeserver, and Plan origins")
		}
	} else if !hasTestEnvironmentMarker(c.MatrixDeployment) ||
		!serverNameMarkedTest || !homeserverMarkedTest || !planMarkedTest {
		return fmt.Errorf("non-production MATRIX_DEPLOYMENT_ID, SERVER_NAME, HOMESERVER, and PLAN_PUBLIC_URL must carry a test/sandbox/staging marker")
	}
	if c.BillingEnv == "production" && (c.MatrixDeployment != "production" || planMarkedTest || homeserverMarkedTest || serverNameMarkedTest || dbMarkedTest) {
		return fmt.Errorf("BILLING_ENV=production is incompatible with test/sandbox/staging deployment, server, Homeserver, Plan, or database identifiers")
	}
	if err := validateComposeInternalOrigin(c.SynapseAdminURL, "synapse", "8008", "SYNAPSE_ADMIN_URL"); err != nil {
		return err
	}
	if err := validateComposeInternalOrigin(c.MASBaseURL, "mas", "8080", "MAS_BASE_URL"); err != nil {
		return err
	}
	return nil
}

func samePublicURL(u *url.URL, expectedOrigin, expectedPath string) bool {
	return strings.EqualFold(u.Scheme+"://"+u.Host, expectedOrigin) &&
		strings.TrimSuffix(u.Path, "/") == expectedPath
}

func validateComposeInternalOrigin(raw, host, port, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() != host || u.Port() != port ||
		(u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be the Compose-local origin http://%s:%s", name, host, port)
	}
	return nil
}

func hasTestEnvironmentMarker(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{"test", "sandbox", "staging"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}
