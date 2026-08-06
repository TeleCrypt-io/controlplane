// Package masadmin is a client for MAS's admin API (v1.16.0) — janitor's one job that
// needs a standing MAS admin credential. Everything below is derived from the MAS v1.16.0 source
// (github.com/element-hq/matrix-authentication-service, tag v1.16.0), not guessed:
//
//   - crates/router/src/endpoints.rs — OAuth2TokenEndpoint's path is "/oauth2/token" (same
//     no-/auth-prefix convention used against the private MAS origin).
//   - crates/handlers/src/oauth2/token.rs (client_credentials_grant) and
//     crates/axum-utils/src/client_authorization.rs (Credentials::verify) — client_credentials
//     authentication is checked against the client's *registered* token_endpoint_auth_method:
//     ClientSecretPost only matches a client configured for client_secret_post, ClientSecretBasic
//     only matches one configured for client_secret_basic. The admin client here is provisioned
//     as client_secret_basic, so sending the secret in the POST body instead of the Authorization
//     header fails with a misleading invalid_client — learned the hard way, per the task brief.
//     This client always sends HTTP Basic.
//   - crates/handlers/src/admin/mod.rs — the whole admin API is mounted at "/api/admin/v1".
//   - crates/handlers/src/admin/call_context.rs — every admin endpoint requires a bearer token
//     whose session scope contains "urn:mas:admin".
//   - crates/handlers/src/admin/v1/users/list.rs — GET /api/admin/v1/users returns User
//     resources: {username, created_at, locked_at, deactivated_at, admin, legacy_guest}. No email
//     field on User itself — see user_emails below for email presence.
//   - crates/handlers/src/admin/v1/users/{lock,unlock}.rs — POST
//     /api/admin/v1/users/{ulid}/{lock,unlock} changes the reversible account lock. This is not
//     deactivation; unlock also leaves a separately deactivated account deactivated.
//   - crates/handlers/src/admin/v1/user_emails/list.rs — GET /api/admin/v1/user-emails returns
//     UserEmail resources: {created_at, user_id, email}. Supports filter[user]=<ulid> but is also
//     listable unfiltered, so ListUserEmails fetches the whole list once per sweep and the caller
//     builds a user_id set locally, rather than this client issuing one filtered query per user.
//   - crates/handlers/src/admin/params.rs, crates/handlers/src/admin/response.rs — cursor
//     pagination: page[first]=N to page forward, page[after]=<cursor> to continue (the cursor is
//     just the previous page's last resource ID); count=false skips MAS's incidental COUNT(*)
//     query since this client never needs a total; a response's "links.next" key is present iff
//     there is a next page.
//
// Flagged for the live spike: expires_in is trusted as returned rather than hardcoded to any
// particular value (the task brief says ~300s); the exact number of admin-scoped users/emails in
// prod, and whether MAS's default page size assumption holds up, are unverified outside this
// package's tests against a fake server.
package masadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUserNotFound is returned by LockUser or UnlockUser when MAS reports the ULID doesn't exist
// (404).
var ErrUserNotFound = errors.New("masadmin: user not found")

// CreatedUser and PersonalSession are the minimum MAS Admin API fields needed by the private
// agent issuer. Personal access tokens are returned only once, at session creation.
type CreatedUser struct {
	ID       string
	Username string
}

type PersonalSession struct {
	ID          string
	AccessToken string
}

// listPageSize is the page[first] value used for both ListUsers and ListUserEmails. MAS's own
// default (10, per admin/params.rs) is fine correctness-wise but wasteful for a sweep that always
// wants the full list — a larger page keeps the round-trip count low without guessing at prod
// scale.
const listPageSize = 100

// tokenSafetyMargin keeps a cached token from being handed out so close to its ~300s expiry that
// it might lapse mid-request.
const tokenSafetyMargin = 15 * time.Second

// Client talks to one MAS deployment's admin API, holding a standing client_credentials
// (client_secret_basic) admin credential. Safe for concurrent use.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// NewClient targets the given MAS base URL (e.g. http://mas:8080, no /auth prefix) with the given admin
// client_credentials client_id/client_secret.
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

// User is one MAS account, as returned by GET /api/admin/v1/users.
type User struct {
	ID            string // ULID
	Username      string
	CreatedAt     time.Time
	LockedAt      *time.Time
	DeactivatedAt *time.Time
	Admin         bool
	LegacyGuest   bool
}

// UserEmail is one email attached to a MAS account, as returned by GET /api/admin/v1/user-emails.
type UserEmail struct {
	ID        string // ULID
	UserID    string // the owning user's ULID
	Email     string
	CreatedAt time.Time
}

// token returns a valid bearer token, fetching a fresh one via client_credentials if the cached
// one is missing or within tokenSafetyMargin of expiry. Never cached indefinitely — the ~300s TTL
// means a long-running ticker will refetch several times an hour, and RUN_ONCE always fetches
// fresh since there's nothing yet to cache.
func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry.Add(-tokenSafetyMargin)) {
		return c.cachedToken, nil
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"urn:mas:admin"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth2/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret) // client_secret_basic — see package doc

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("masadmin: fetch token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("masadmin: fetch token: %s", describeError(resp))
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("masadmin: decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("masadmin: token response had no access_token")
	}

	c.cachedToken = out.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return c.cachedToken, nil
}

// resource is one JSON:API-ish resource envelope, shared by users and user-emails responses.
type resource[T any] struct {
	ID         string `json:"id"`
	Attributes T      `json:"attributes"`
}

type paginatedResponse[T any] struct {
	Data  []resource[T] `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type userAttrs struct {
	Username      string     `json:"username"`
	CreatedAt     time.Time  `json:"created_at"`
	LockedAt      *time.Time `json:"locked_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
	Admin         bool       `json:"admin"`
	LegacyGuest   bool       `json:"legacy_guest"`
}

type emailAttrs struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
}

// CreateUser creates a passwordless MAS user. Authentication is supplied by the client's
// short-lived OAuth client-credentials token; no compatibility login or user password exists.
func (c *Client) CreateUser(ctx context.Context, username string) (CreatedUser, error) {
	body, err := json.Marshal(struct {
		Username string `json:"username"`
	}{Username: username})
	if err != nil {
		return CreatedUser{}, err
	}
	var out struct {
		Data resource[userAttrs] `json:"data"`
	}
	if err := c.postJSON(ctx, "/api/admin/v1/users", body, http.StatusCreated, &out); err != nil {
		return CreatedUser{}, fmt.Errorf("masadmin: create user: %w", err)
	}
	if out.Data.ID == "" || out.Data.Attributes.Username != username {
		return CreatedUser{}, fmt.Errorf("masadmin: create user returned unexpected identity")
	}
	return CreatedUser{ID: out.Data.ID, Username: out.Data.Attributes.Username}, nil
}

// CreatePersonalSession issues a revocable bot credential acting only as actorUserID with the
// supplied Matrix client/device scopes. A nil expiresIn deliberately creates a non-expiring PAT;
// callers must document and provide an administrative revocation path.
func (c *Client) CreatePersonalSession(ctx context.Context, actorUserID, humanName, scope string, expiresIn *uint32) (PersonalSession, error) {
	body, err := json.Marshal(struct {
		ActorUserID string  `json:"actor_user_id"`
		HumanName   string  `json:"human_name"`
		Scope       string  `json:"scope"`
		ExpiresIn   *uint32 `json:"expires_in"`
	}{actorUserID, humanName, scope, expiresIn})
	if err != nil {
		return PersonalSession{}, err
	}
	var out struct {
		Data resource[struct {
			AccessToken *string `json:"access_token"`
		}] `json:"data"`
	}
	if err := c.postJSON(ctx, "/api/admin/v1/personal-sessions", body, http.StatusCreated, &out); err != nil {
		return PersonalSession{}, fmt.Errorf("masadmin: create personal session: %w", err)
	}
	if out.Data.ID == "" || out.Data.Attributes.AccessToken == nil || *out.Data.Attributes.AccessToken == "" {
		return PersonalSession{}, fmt.Errorf("masadmin: personal session response had no access token")
	}
	return PersonalSession{ID: out.Data.ID, AccessToken: *out.Data.Attributes.AccessToken}, nil
}

// DeactivateUser is compensating cleanup when account creation succeeds but PAT issuance fails.
func (c *Client) DeactivateUser(ctx context.Context, userID string) error {
	if err := c.postJSON(ctx, "/api/admin/v1/users/"+url.PathEscape(userID)+"/deactivate", []byte(`{}`), http.StatusOK, nil); err != nil {
		return fmt.Errorf("masadmin: deactivate user %s: %w", userID, err)
	}
	return nil
}

// ListUsers returns every MAS user account, paging through the full result set via page[after]
// cursors.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	after := ""
	for {
		var page paginatedResponse[userAttrs]
		if err := c.get(ctx, "/api/admin/v1/users?"+listQuery(after), &page); err != nil {
			return nil, fmt.Errorf("masadmin: list users: %w", err)
		}
		for _, r := range page.Data {
			out = append(out, User{
				ID:            r.ID,
				Username:      r.Attributes.Username,
				CreatedAt:     r.Attributes.CreatedAt,
				LockedAt:      r.Attributes.LockedAt,
				DeactivatedAt: r.Attributes.DeactivatedAt,
				Admin:         r.Attributes.Admin,
				LegacyGuest:   r.Attributes.LegacyGuest,
			})
		}
		if page.Links.Next == "" || len(page.Data) == 0 {
			break
		}
		after = page.Data[len(page.Data)-1].ID
	}
	return out, nil
}

// ListUserEmails returns every email attached to any MAS account, paging through the full result
// set via page[after] cursors. Unfiltered — the caller builds a user_id set locally rather than
// this client issuing one filtered (filter[user]=...) query per candidate user.
func (c *Client) ListUserEmails(ctx context.Context) ([]UserEmail, error) {
	var out []UserEmail
	after := ""
	for {
		var page paginatedResponse[emailAttrs]
		if err := c.get(ctx, "/api/admin/v1/user-emails?"+listQuery(after), &page); err != nil {
			return nil, fmt.Errorf("masadmin: list user emails: %w", err)
		}
		for _, r := range page.Data {
			out = append(out, UserEmail{
				ID:        r.ID,
				UserID:    r.Attributes.UserID,
				Email:     r.Attributes.Email,
				CreatedAt: r.Attributes.CreatedAt,
			})
		}
		if page.Links.Next == "" || len(page.Data) == 0 {
			break
		}
		after = page.Data[len(page.Data)-1].ID
	}
	return out, nil
}

func listQuery(after string) string {
	v := url.Values{}
	v.Set("count", "false")
	v.Set("page[first]", strconv.Itoa(listPageSize))
	if after != "" {
		v.Set("page[after]", after)
	}
	return v.Encode()
}

// LockUser locks the given MAS user (by ULID) — reversible, not a deactivation — and returns
// MAS's exact locked_at timestamp for durable provenance. Returns ErrUserNotFound if MAS reports
// no such user.
func (c *Client) LockUser(ctx context.Context, userID string) (time.Time, error) {
	attrs, err := c.setUserLock(ctx, userID, "lock")
	if err != nil {
		return time.Time{}, err
	}
	if attrs.LockedAt == nil {
		return time.Time{}, fmt.Errorf("masadmin: lock user %s: response had no locked_at", userID)
	}
	return *attrs.LockedAt, nil
}

// UnlockUser removes the reversible lock from the given MAS user (by ULID). It does not
// reactivate a deactivated user. Returns ErrUserNotFound if MAS reports no such user.
func (c *Client) UnlockUser(ctx context.Context, userID string) error {
	attrs, err := c.setUserLock(ctx, userID, "unlock")
	if err != nil {
		return err
	}
	if attrs.LockedAt != nil {
		return fmt.Errorf("masadmin: unlock user %s: response still had locked_at", userID)
	}
	return nil
}

func (c *Client) setUserLock(ctx context.Context, userID, action string) (userAttrs, error) {
	token, err := c.token(ctx)
	if err != nil {
		return userAttrs{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/admin/v1/users/"+url.PathEscape(userID)+"/"+action, nil)
	if err != nil {
		return userAttrs{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return userAttrs{}, fmt.Errorf("masadmin: %s user %s: %w", action, userID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return userAttrs{}, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}
	if resp.StatusCode != http.StatusOK {
		return userAttrs{}, fmt.Errorf("masadmin: %s user %s: %s", action, userID, describeError(resp))
	}
	var out struct {
		Data resource[userAttrs] `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return userAttrs{}, fmt.Errorf("masadmin: decode %s user %s: %w", action, userID, err)
	}
	return out.Data.Attributes, nil
}

// get issues an authenticated GET against path (relative to baseURL) and decodes a 200 JSON body
// into out.
func (c *Client) get(ctx context.Context, path string, out any) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", describeError(resp))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) postJSON(ctx context.Context, path string, body []byte, wantStatus int, out any) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("%s", describeError(resp))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// describeError makes a best-effort attempt to surface MAS's {"errors":[{"title":...}]} error
// envelope (see admin/response.rs's ErrorResponse) for diagnostics.
func describeError(resp *http.Response) string {
	body, _ := io.ReadAll(resp.Body)

	var e struct {
		Errors []struct {
			Title string `json:"title"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		titles := make([]string, len(e.Errors))
		for i, er := range e.Errors {
			titles[i] = er.Title
		}
		return fmt.Sprintf("status %d: %s", resp.StatusCode, strings.Join(titles, "; "))
	}
	return fmt.Sprintf("status %d: %s", resp.StatusCode, string(body))
}
