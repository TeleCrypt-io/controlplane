// Package masreg drives MAS 1.23.0's public password-registration and OAuth device flows as a
// plain HTTP client — the same request sequence a browser runs, with no admin credentials or
// pre-registered OAuth client involved.
//
// The endpoint sequence and form field names below implement the MAS 1.23.0 public contract:
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
//   - crates/handlers/src/oauth2/device/link.rs — GET /link returns a CSRF-protected form;
//     POST /link with the echoed token and user code redirects (303) to the consent page.
//   - templates/pages/register/password.html, templates/pages/register/steps/display_name.html —
//     exact input names, including the hidden "csrf" and "action" fields.
//
// Every step's success response is a 303 redirect. net/http.Client's default redirect policy
// converts a POST into a followed GET on a 303, so the registration part of
// RegisterAndAuthorizeDevice issues one explicit HTTP call per logical step and lets the client
// follow the intermediate hops transparently — the same way a browser would.
package masreg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
// RegisterAndAuthorizeDevice call runs in its own session with a fresh cookie jar. The jar
// isolation matters even for strictly sequential calls — a jar reused across registrations would
// present the previous account's live MAS session cookie on the next GET /register, and MAS
// redirects an already-authenticated visitor away from the form instead of serving it.
type Client struct {
	baseURL string
}

// NewClient targets the given MAS base URL (e.g. http://mas:8080, no /auth prefix).
func NewClient(baseURL string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/")}
}

// session is the HTTP state of one RegisterAndAuthorizeDevice call: one cookie jar, one client,
// discarded after.
type session struct {
	baseURL          string
	httpClient       *http.Client
	publicHTTPClient *http.Client // test seam; production always uses the credential-free default below
}

// DeviceTokens is the complete, short-lived result of the public OAuth device grant. Its client
// ID and token endpoint are returned because the caller must retain them to refresh the token;
// masreg itself keeps no state after RegisterAndAuthorizeDevice returns.
type DeviceTokens struct {
	AccessToken   string
	RefreshToken  string
	ExpiresIn     int
	ClientID      string
	Issuer        string
	TokenEndpoint string
	UserID        string
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

// RegisterAndAuthorizeDevice creates an account through MAS's public forms, dynamically
// registers a public native OAuth client, grants a Matrix device through the authenticated MAS
// session, and polls the public token endpoint. The cookie jar is local to this call and is
// discarded before return.
func (c *Client) RegisterAndAuthorizeDevice(
	ctx context.Context, username, password, deviceID, clientURI string,
) (*DeviceTokens, error) {
	s, err := c.registerSession(ctx, username, password)
	if err != nil {
		return nil, err
	}
	clientID, err := s.registerPublicNativeClient(ctx, clientURI)
	if err != nil {
		return nil, fmt.Errorf("register public OAuth client: %w", err)
	}
	device, err := s.startDeviceAuthorization(ctx, clientID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("start device authorization: %w", err)
	}
	if err := s.approveDeviceAuthorization(ctx, device.UserCode); err != nil {
		return nil, fmt.Errorf("approve device authorization: %w", err)
	}
	tokens, err := s.pollDeviceToken(ctx, clientID, device)
	if err != nil {
		return nil, fmt.Errorf("poll device token: %w", err)
	}
	tokens.ClientID = clientID
	// MAS's issuer is its configured base URI, whose canonical form has a trailing slash.
	tokens.Issuer = c.baseURL + "/"
	tokens.TokenEndpoint = c.baseURL + "/oauth2/token"
	userID, returnedDeviceID, err := s.whoAmI(ctx, clientURI, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("validate OAuth token identity: %w", err)
	}
	if returnedDeviceID != deviceID {
		return nil, fmt.Errorf("OAuth token returned unexpected device_id %q", returnedDeviceID)
	}
	tokens.UserID = userID
	return tokens, nil
}

func (c *Client) registerSession(ctx context.Context, username, password string) (*session, error) {
	jar, _ := cookiejar.New(nil) // nil PublicSuffixList: this client only ever talks to one host
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse MAS base URL: %w", err)
	}
	s := &session{
		baseURL: c.baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("MAS registration exceeded redirect limit")
				}
				if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host {
					return errors.New("MAS redirected outside its configured origin")
				}
				return nil
			},
		},
	}
	if err := s.register(ctx, username, password); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *session) publicClient() *http.Client {
	if s.publicHTTPClient != nil {
		return s.publicHTTPClient
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		// Public OAuth endpoints must never redirect: a 307/308 could otherwise replay a device
		// code or bearer token to an attacker-controlled origin.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c *session) register(ctx context.Context, username, password string) error {
	// Step 1: GET /register -> (redirect, followed automatically) -> /register/password form.
	csrf, formURL, body, err := c.getForm(ctx, c.baseURL+"/register")
	if err != nil {
		return fmt.Errorf("masreg: load register form: %w", err)
	}
	if !c.isRegistrationPath(formURL.Path) || !strings.HasSuffix(formURL.Path, "/register/password") {
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
	if !c.isRegistrationPath(formURL.Path) || !strings.Contains(formURL.Path, "/register/steps/") || !strings.HasSuffix(formURL.Path, "/display-name") {
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
	if c.isRegistrationPath(formURL.Path) {
		return fmt.Errorf("masreg: registration did not complete, still on %q: %s",
			formURL.Path, sniffError(body))
	}

	return nil
}

// isRegistrationPath accounts for MAS being published below a path prefix (for example
// https://backend.telecrypt.io/auth/). Redirects that stay inside /auth/register are incomplete
// registration, even though they do not begin at the origin root.
func (c *session) isRegistrationPath(path string) bool {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return false
	}
	prefix := strings.TrimRight(base.Path, "/") + "/register"
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

type deviceAuthorization struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

func (s *session) registerPublicNativeClient(ctx context.Context, clientURI string) (string, error) {
	payload := struct {
		ClientName              string   `json:"client_name"`
		ClientURI               string   `json:"client_uri"`
		RedirectURIs            []string `json:"redirect_uris"`
		ApplicationType         string   `json:"application_type"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
	}{
		ClientName:              "TeleCrypt Redpill agent",
		ClientURI:               clientURI,
		RedirectURIs:            []string{clientURI},
		ApplicationType:         "native",
		TokenEndpointAuthMethod: "none",
		GrantTypes: []string{
			"urn:ietf:params:oauth:grant-type:device_code",
			"refresh_token",
		},
		ResponseTypes: []string{},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	// MAS 1.23.0's DynamicClientRegistration route is /oauth2/registration. The grant types
	// are explicit: MAS otherwise defaults to authorization_code, which cannot issue this device
	// grant or its refresh token.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/oauth2/registration", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.publicClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", unexpectedStatus(resp)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.ClientID == "" {
		return "", fmt.Errorf("response has no client_id")
	}
	return out.ClientID, nil
}

func (s *session) startDeviceAuthorization(ctx context.Context, clientID, deviceID string) (*deviceAuthorization, error) {
	form := url.Values{
		"client_id": {clientID},
		"scope":     {"openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:" + deviceID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/oauth2/device", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.publicClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, unexpectedStatus(resp)
	}
	var out deviceAuthorization
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" || out.ExpiresIn <= 0 {
		return nil, fmt.Errorf("response is missing device authorization fields")
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	return &out, nil
}

func (s *session) approveDeviceAuthorization(ctx context.Context, userCode string) error {
	// MAS 1.23's /link page is a CSRF-protected GET form. POSTing its token and
	// the user code redirects (303) to the consent page, which has its own CSRF
	// token. See
	// crates/handlers/src/oauth2/device/link.rs and
	// templates/pages/device_link.html in matrix-authentication-service v1.23.0.
	linkURL, err := url.Parse(s.baseURL + "/link")
	if err != nil {
		return fmt.Errorf("parse device link URL: %w", err)
	}
	csrf, formURL, body, err := s.getForm(ctx, linkURL.String())
	if err != nil {
		return fmt.Errorf("load device link: %w", err)
	}
	if formURL == nil || formURL.Path != linkURL.Path {
		path := "<nil>"
		if formURL != nil {
			path = formURL.Path
		}
		return fmt.Errorf("device link form landed at %q: %s", path, sniffError(body))
	}
	if csrf == "" {
		return fmt.Errorf("no csrf token found on device link form: %s", sniffError(body))
	}
	csrf, consentURL, body, err := s.postForm(ctx, formURL.String(), url.Values{
		"csrf": {csrf},
		"code": {userCode},
	})
	if err != nil {
		return fmt.Errorf("submit device code: %w", err)
	}
	if consentURL == nil || !s.isDeviceConsentPath(consentURL.Path) {
		path := "<nil>"
		if consentURL != nil {
			path = consentURL.Path
		}
		return fmt.Errorf("device link did not redirect to consent: %q: %s", path, sniffError(body))
	}
	if csrf == "" {
		return fmt.Errorf("no csrf token found on device consent page: %s", sniffError(body))
	}
	_, _, _, err = s.postForm(ctx, consentURL.String(), url.Values{
		"csrf":           {csrf},
		"confirm_device": {"on"},
		"action":         {"consent"},
	})
	if err != nil {
		return fmt.Errorf("submit device consent: %w", err)
	}
	return nil
}

func (s *session) isDeviceConsentPath(path string) bool {
	base, err := url.Parse(s.baseURL)
	if err != nil {
		return false
	}
	prefix := strings.TrimRight(base.Path, "/") + "/device/"
	return strings.HasPrefix(path, prefix) && len(path) > len(prefix)
}

func (s *session) pollDeviceToken(ctx context.Context, clientID string, device *deviceAuthorization) (*DeviceTokens, error) {
	deadline := time.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	interval := time.Duration(device.Interval) * time.Second
	for {
		form := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {device.DeviceCode},
			"client_id":   {clientID},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/oauth2/token", strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := s.publicClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err := waitForRetry(ctx, interval, deadline); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err := waitForRetry(ctx, interval, deadline); err != nil {
				return nil, err
			}
			continue
		}
		var out struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			Error        string `json:"error"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode response: %w", decodeErr)
		}
		if resp.StatusCode == http.StatusOK {
			if out.AccessToken == "" || out.RefreshToken == "" || out.ExpiresIn <= 0 {
				return nil, fmt.Errorf("token response is missing access_token, refresh_token, or expires_in")
			}
			return &DeviceTokens{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, ExpiresIn: out.ExpiresIn}, nil
		}
		if out.Error != "authorization_pending" && out.Error != "slow_down" {
			return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		if out.Error == "slow_down" {
			interval += 5 * time.Second
		}
		if err := waitForRetry(ctx, interval, deadline); err != nil {
			return nil, err
		}
	}
}

func waitForRetry(ctx context.Context, interval time.Duration, deadline time.Time) error {
	if time.Now().Add(interval).After(deadline) {
		return fmt.Errorf("device authorization expired")
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *session) whoAmI(ctx context.Context, homeserver, accessToken string) (string, string, error) {
	u, err := url.Parse(homeserver)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("invalid homeserver URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/_matrix/client/v3/account/whoami"
	u.RawQuery = ""
	u.Fragment = ""
	for attempt, delay := 0, 100*time.Millisecond; attempt < 6; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		resp, err := s.publicClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return "", "", ctx.Err()
			}
			if attempt == 5 {
				return "", "", fmt.Errorf("identity transport failure after retries: %w", err)
			}
			if err := waitForContext(ctx, delay); err != nil {
				return "", "", err
			}
			delay *= 2
			continue
		}
		if resp.StatusCode == http.StatusOK {
			var out struct {
				UserID   string `json:"user_id"`
				DeviceID string `json:"device_id"`
			}
			err := json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if err != nil {
				return "", "", fmt.Errorf("decode response: %w", err)
			}
			if out.UserID == "" || out.DeviceID == "" {
				return "", "", fmt.Errorf("response is missing user_id or device_id")
			}
			return out.UserID, out.DeviceID, nil
		}
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < http.StatusInternalServerError {
			err := unexpectedStatus(resp)
			return "", "", err
		}
		resp.Body.Close()
		if attempt == 5 {
			return "", "", fmt.Errorf("identity was not ready after retries")
		}
		if err := waitForContext(ctx, delay); err != nil {
			return "", "", err
		}
		delay *= 2
	}
	return "", "", fmt.Errorf("identity was not ready")
}

func waitForContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func unexpectedStatus(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read status response: %w", err)
	}
	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, sniffError(body))
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
