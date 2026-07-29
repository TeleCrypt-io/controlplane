// Package masreg drives MAS 1.16.0's public, unauthenticated password-registration form as a
// plain HTTP client — the same request sequence a browser runs, with no admin credentials
// involved. This replaces the old admin-API-based provisioning (mas.Client.CreateUser +
// SetPassword) now that redpill holds no MAS admin credentials at all.
//
// The endpoint sequence and form field names below are derived from the MAS v1.16.0 source
// (github.com/element-hq/matrix-authentication-service, tag v1.16.0):
//   - crates/handlers/src/views/register/mod.rs — GET /register redirects (303) straight to
//     /register/password when password registration is enabled and no upstream OAuth provider
//     is configured; otherwise it renders a combined provider-choice page instead (not handled
//     here — see the package-level "assumes no upstream OAuth provider" note below).
//   - crates/router/src/endpoints.rs — route paths: PasswordRegister is "/register/password",
//     RegisterDisplayName is "/register/steps/{id}/display-name", RegisterFinish is
//     "/register/steps/{id}/finish".
//   - crates/handlers/src/views/register/password.rs — RegisterForm{username, email, password,
//     password_confirm, accept_terms}; on success redirects (303) to RegisterFinish.
//   - crates/handlers/src/views/register/steps/finish.rs — GET is the orchestrator: redirects to
//     whichever step (registration token / verify-email / display-name) isn't done yet, then
//     completes the registration (creates the MAS user row) and redirects away from /register.
//   - crates/handlers/src/views/register/steps/display_name.rs — DisplayNameForm{action,
//     display_name}; action="skip" makes MAS default the display name to the username, the same
//     default Synapse itself would pick.
//   - crates/axum-utils/src/csrf.rs — ProtectedForm: the CSRF token lives in an opaque "csrf"
//     cookie (cookiejar carries it automatically) and must be echoed back as a hidden "csrf" form
//     field; there is no Origin/Referer check, only the token match.
//   - templates/pages/register/password.html, templates/pages/register/steps/display_name.html —
//     exact input names, including the hidden "csrf" and "action" fields.
//
// Every step's success response is a 303 redirect. net/http.Client's default redirect policy
// converts a POST into a followed GET on a 303, so Register below issues one explicit HTTP call
// per logical step and lets the client follow the intermediate hops transparently — the same way
// a browser would.
package masreg

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Client drives the registration flow against one MAS deployment. Safe for concurrent use: each
// Register call runs in its own session with a fresh cookie jar. The jar isolation matters even
// for strictly sequential calls — a jar reused across registrations would present the previous
// account's live MAS session cookie on the next GET /register, and MAS redirects an
// already-authenticated visitor away from the form instead of serving it.
type Client struct {
	baseURL string
}

// NewClient targets the given MAS base URL (e.g. http://mas:8080, no /auth prefix — same
// convention as internal/synapse.NewClient).
func NewClient(baseURL string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/")}
}

// session is the HTTP state of one Register call: one cookie jar, one client, discarded after.
type session struct {
	baseURL    string
	httpClient *http.Client
}

var csrfFieldRe = regexp.MustCompile(`name="csrf"\s+value="([^"]*)"`)

// extractCSRF returns "" if the page has no CSRF field — true of the final landing page after
// registration completes, which callers that no longer need a token simply ignore.
func extractCSRF(body []byte) string {
	m := csrfFieldRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// Register drives the full public registration flow for the given username/password and returns
// once MAS has created the account. It does not itself log the caller in — call
// synapse.Client.CompatLogin afterwards to mint an access token.
//
// Assumes (unverified outside a live spike): password registration is enabled, no upstream OAuth
// provider is configured (so GET /register redirects straight to /register/password), email is
// not required (password_registration_email_required is false), no CAPTCHA is configured, and no
// registration token is required. Any of these being true in prod would make Register fail
// closed with a descriptive error rather than silently mis-register.
func (c *Client) Register(ctx context.Context, username, password string) error {
	jar, _ := cookiejar.New(nil) // nil PublicSuffixList: this client only ever talks to one host
	s := &session{
		baseURL: c.baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
		},
	}
	return s.register(ctx, username, password)
}

func (c *session) register(ctx context.Context, username, password string) error {
	// Step 1: GET /register -> (redirect, followed automatically) -> /register/password form.
	csrf, formURL, body, err := c.getForm(ctx, c.baseURL+"/register")
	if err != nil {
		return fmt.Errorf("masreg: load register form: %w", err)
	}
	if !strings.HasSuffix(formURL.Path, "/register/password") {
		return fmt.Errorf("masreg: expected to land on /register/password, got %q — "+
			"is an upstream OAuth provider configured alongside password registration?", formURL.Path)
	}
	if csrf == "" {
		return fmt.Errorf("masreg: no csrf token found on the password registration page: %s", sniffError(body))
	}

	// Step 2: POST /register/password. Field names from password.html / password.rs's
	// RegisterForm. Email is deliberately left blank per the target provisioning flow.
	form := url.Values{
		"csrf":             {csrf},
		"username":         {username},
		"email":            {""},
		"password":         {password},
		"password_confirm": {password},
		"accept_terms":     {"on"}, // no-op if this deployment has no tos_uri configured
	}
	csrf, formURL, body, err = c.postForm(ctx, formURL.String(), form)
	if err != nil {
		return fmt.Errorf("masreg: submit password form: %w", err)
	}
	if !strings.Contains(formURL.Path, "/register/steps/") || !strings.HasSuffix(formURL.Path, "/display-name") {
		return fmt.Errorf("masreg: expected to land on the display-name step, got %q: %s",
			formURL.Path, sniffError(body))
	}
	if csrf == "" {
		return fmt.Errorf("masreg: no csrf token found on the display-name step page: %s", sniffError(body))
	}

	// Step 3: POST .../display-name with action=skip (display_name.rs: skip defaults the
	// display name to the username). The finish step (steps/finish.rs GET) then completes the
	// registration synchronously and redirects away from /register entirely.
	form = url.Values{
		"csrf":   {csrf},
		"action": {"skip"},
	}
	_, formURL, body, err = c.postForm(ctx, formURL.String(), form)
	if err != nil {
		return fmt.Errorf("masreg: submit display-name step: %w", err)
	}
	if strings.HasPrefix(formURL.Path, "/register") {
		return fmt.Errorf("masreg: registration did not complete, still on %q: %s",
			formURL.Path, sniffError(body))
	}

	return nil
}

func (c *session) getForm(ctx context.Context, target string) (csrf string, finalURL *url.URL, body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, nil, err
	}
	return c.do(req)
}

func (c *session) postForm(ctx context.Context, target string, form url.Values) (csrf string, finalURL *url.URL, body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

// do issues req (following any redirects, per the package doc), and extracts the CSRF token from
// the final landing page's hidden form field so the caller can echo it in the next step.
func (c *session) do(req *http.Request) (csrf string, finalURL *url.URL, body []byte, err error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, nil, fmt.Errorf("unexpected status %d at %s: %s",
			resp.StatusCode, resp.Request.URL, sniffError(body))
	}
	return extractCSRF(body), resp.Request.URL, body, nil
}

var formErrorRe = regexp.MustCompile(`text-critical[^>]*>\s*([^<]+)`)

// sniffError makes a best-effort attempt to pull a human-readable validation message out of a
// MAS-rendered error page for diagnostics. Never includes the password — MAS's own error
// rendering doesn't echo submitted field values back for password fields, and this function only
// ever reads the response body, never the request.
func sniffError(body []byte) string {
	m := formErrorRe.FindSubmatch(body)
	if m == nil {
		return "no error text found in response body"
	}
	return strings.TrimSpace(string(m[1]))
}
