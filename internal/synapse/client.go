// Package synapse is a client for compat login — the call that mints the agent's constant
// access token. Validated against a live Synapse 1.155.0 / MAS 1.16.0 stack (Phase -1 spike +
// pre-Phase-1 validation, see implementation_plan.md §8).
//
// Under MSC3861 delegated auth, the legacy compat login endpoint is served by MAS, not Synapse
// itself — confirmed both by Caddy's routing (@mas_compat matches /_matrix/client/*/login and
// sends it to mas:8080) and by `mas-cli doctor`.
package synapse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	compatBaseURL string // MAS — serves the compat login endpoint under MSC3861
	httpClient    *http.Client
}

func NewClient(compatBaseURL string) *Client {
	return &Client{
		compatBaseURL: strings.TrimRight(compatBaseURL, "/"),
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}
}

type LoginResult struct {
	UserID      string
	AccessToken string
}

// CompatLoginError preserves enough information for the provisioning layer to distinguish a
// transient MAS/Synapse readiness failure from a permanent authentication or request failure.
// MAS returns a 5xx briefly when its asynchronous post-registration provisioning job has not yet
// made the new user visible to Synapse.
type CompatLoginError struct {
	StatusCode int
	Err        error
}

func (e *CompatLoginError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("compat login: unexpected status %d", e.StatusCode)
	}
	return fmt.Sprintf("compat login: %v", e.Err)
}

func (e *CompatLoginError) Unwrap() error {
	return e.Err
}

// IsRetryableCompatLogin reports whether retrying the same compatibility login is safe and
// useful. Client and authentication errors deliberately fail closed without retrying.
func IsRetryableCompatLogin(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var loginErr *CompatLoginError
	if !errors.As(err, &loginErr) {
		return false
	}
	return loginErr.Err != nil || loginErr.StatusCode >= http.StatusInternalServerError
}

// CompatLogin logs in with m.login.password, deliberately omitting refresh_token — the
// Phase -1 spike confirmed that's what makes the resulting access token non-expiring. This call
// also lazily creates the Synapse-side user row for a MAS-created user on first login.
func (c *Client) CompatLogin(ctx context.Context, username, password, deviceID string) (*LoginResult, error) {
	reqBody := map[string]any{
		"type": "m.login.password",
		"identifier": map[string]string{
			"type": "m.id.user",
			"user": username,
		},
		"password":  password,
		"device_id": deviceID,
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.compatBaseURL+"/_matrix/client/v3/login",
		bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &CompatLoginError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &CompatLoginError{StatusCode: resp.StatusCode}
	}

	var out struct {
		UserID      string `json:"user_id"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("compat login response: %w", err)
	}
	return &LoginResult{UserID: out.UserID, AccessToken: out.AccessToken}, nil
}
