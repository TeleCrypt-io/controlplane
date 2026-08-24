// Package masadmin is a client for MAS 1.23.0's admin API — janitor's one job that
// needs a standing MAS admin credential. The paths, authentication, response fields, and
// pagination below implement MAS's current admin API contract:
//
//   - crates/router/src/endpoints.rs — OAuth2TokenEndpoint's path is "/oauth2/token" (same
//     no-/auth-prefix convention internal/masreg already uses against the MAS internal origin).
//   - crates/handlers/src/oauth2/token.rs (client_credentials_grant) and
//     crates/axum-utils/src/client_authorization.rs (Credentials::verify) — client_credentials
//     authentication is checked against the client's *registered* token_endpoint_auth_method:
//     ClientSecretPost only matches a client configured for client_secret_post, ClientSecretBasic
//     only matches one configured for client_secret_basic. The admin client here is provisioned
//     as client_secret_basic, so sending the secret in the POST body instead of the Authorization
//     header fails with invalid_client. This client always sends HTTP Basic.
//   - crates/handlers/src/admin/mod.rs — the whole admin API is mounted at "/api/admin/v1".
//   - crates/handlers/src/admin/call_context.rs — every admin endpoint requires a bearer token
//     whose session scope contains "urn:mas:admin".
//   - crates/handlers/src/admin/v1/users/list.rs — GET /api/admin/v1/users returns User
//     resources with username, created_at, locked_at, and deactivated_at. No email field on User
//     itself — see user_emails below for email presence.
//   - crates/handlers/src/admin/v1/users/lock.rs — POST
//     /api/admin/v1/users/{ulid}/lock changes the reversible account lock. Janitor deliberately
//     has no unlock capability because MAS cannot prove which actor created a raced lock.
//   - crates/handlers/src/admin/v1/user_emails/list.rs — GET /api/admin/v1/user-emails returns
//     UserEmail resources: {created_at, user_id, email}. Supports filter[user]=<ulid> but is also
//     listable unfiltered, so ListUserEmails fetches the whole list once per sweep and the caller
//     builds a user_id set locally, rather than this client issuing one filtered query per user.
//   - crates/handlers/src/admin/params.rs, crates/handlers/src/admin/response.rs — cursor
//     pagination: page[first]=N to page forward, page[after]=<cursor> to continue (the cursor is
//     just the previous page's last resource ID); count=false skips MAS's incidental COUNT(*)
//     query since this client never needs a total; a response's "links.next" key is present iff
//     there is a next page.
package masadmin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/TeleCrypt-io/controlplane/internal/jsonbody"
)

// ErrUserNotFound is returned by LockUser when MAS reports the ULID doesn't exist (404).
var ErrUserNotFound = errors.New("masadmin: user not found")

// listPageSize is the page[first] value used for both ListUsers and ListUserEmails. MAS's own
// default (10, per admin/params.rs) is fine correctness-wise but wasteful for a sweep that always
// wants the full list — a larger page keeps the round-trip count low without guessing at prod
// scale.
const listPageSize = 100
const (
	maxListPages = 1000
	maxListItems = 100_000
)

const (
	// Error bodies are intentionally not surfaced: an upstream can echo credentials or other
	// sensitive request material. We still drain a small bounded prefix so the connection can be
	// reused without allowing an unbounded response to consume memory.
	maxErrorBodyBytes         = 8 << 10
	maxJSONBodyBytes          = 1 << 20
	maxMASIdentifierBytes     = 255
	maxMASEmailBytes          = 320
	maxMASTokenBytes          = 8 << 10
	maxMASTokenLifetime       = 24 * time.Hour
	maxMASResponseHeaderBytes = 64 << 10
)

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

// NewClient targets the MAS admin origin (e.g. http://mas-admin:8081, no /auth prefix) with the given
// admin
// client_credentials client_id/client_secret.
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 30 * time.Second, Transport: noProxyTransport(), CheckRedirect: rejectRedirects},
	}
}

// User is one MAS account, as returned by GET /api/admin/v1/users.
type User struct {
	ID            string // ULID
	Username      string
	CreatedAt     time.Time
	LockedAt      *time.Time
	DeactivatedAt *time.Time
}

// UserEmail is one email attached to a MAS account, as returned by GET /api/admin/v1/user-emails.
type UserEmail struct {
	ID        string // ULID
	UserID    string // the owning user's ULID
	Email     string
	CreatedAt time.Time
}

// token returns a valid bearer token, fetching a fresh one via client_credentials if the cached
// one is missing or within tokenSafetyMargin of expiry. A one-shot sweep normally fetches one
// token; the cache also keeps retries within that sweep efficient.
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
		return "", masadminTransportError("masadmin: fetch token", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("masadmin: fetch token: %s", describeError(resp))
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := jsonbody.Decode(resp.Body, maxJSONBodyBytes, &out); err != nil {
		return "", fmt.Errorf("masadmin: decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("masadmin: token response had no access_token")
	}
	if !validMASField(out.AccessToken, maxMASTokenBytes) {
		return "", fmt.Errorf("masadmin: token response had an invalid access_token")
	}
	if out.ExpiresIn <= 0 || out.ExpiresIn > int(maxMASTokenLifetime/time.Second) {
		return "", fmt.Errorf("masadmin: token response had an invalid expires_in")
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
}

type emailAttrs struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
}

// ListUsers returns every MAS user account, paging through the full result set via page[after]
// cursors.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	after := ""
	seenCursors := map[string]struct{}{}
	pageCount := 0
	for {
		pageCount++
		if pageCount > maxListPages {
			return nil, fmt.Errorf("masadmin: list users exceeded page limit")
		}
		var page paginatedResponse[userAttrs]
		if err := c.get(ctx, "/api/admin/v1/users?"+listQuery(after), &page); err != nil {
			return nil, fmt.Errorf("masadmin: list users: %w", err)
		}
		if len(out)+len(page.Data) > maxListItems {
			return nil, fmt.Errorf("masadmin: list users exceeded user limit")
		}
		for _, r := range page.Data {
			if !validMASULID(r.ID) || !validMASUsername(r.Attributes.Username) || r.Attributes.CreatedAt.IsZero() {
				return nil, fmt.Errorf("masadmin: list users returned an invalid user identity")
			}
			out = append(out, User{
				ID:            r.ID,
				Username:      r.Attributes.Username,
				CreatedAt:     r.Attributes.CreatedAt,
				LockedAt:      r.Attributes.LockedAt,
				DeactivatedAt: r.Attributes.DeactivatedAt,
			})
		}
		if page.Links.Next == "" {
			break
		}
		if len(page.Data) == 0 {
			return nil, fmt.Errorf("masadmin: list users returned a next page without data")
		}
		next := page.Data[len(page.Data)-1].ID
		if next == "" || next == after {
			return nil, fmt.Errorf("masadmin: list users returned a non-progressing cursor")
		}
		if _, seen := seenCursors[next]; seen {
			return nil, fmt.Errorf("masadmin: list users returned a cursor cycle")
		}
		seenCursors[next] = struct{}{}
		after = next
	}
	return out, nil
}

// ListUserEmails returns every email attached to any MAS account, paging through the full result
// set via page[after] cursors. Unfiltered — the caller builds a user_id set locally rather than
// this client issuing one filtered (filter[user]=...) query per candidate user.
func (c *Client) ListUserEmails(ctx context.Context) ([]UserEmail, error) {
	var out []UserEmail
	after := ""
	seenCursors := map[string]struct{}{}
	pageCount := 0
	for {
		pageCount++
		if pageCount > maxListPages {
			return nil, fmt.Errorf("masadmin: list user emails exceeded page limit")
		}
		var page paginatedResponse[emailAttrs]
		if err := c.get(ctx, "/api/admin/v1/user-emails?"+listQuery(after), &page); err != nil {
			return nil, fmt.Errorf("masadmin: list user emails: %w", err)
		}
		if len(out)+len(page.Data) > maxListItems {
			return nil, fmt.Errorf("masadmin: list user emails exceeded email limit")
		}
		for _, r := range page.Data {
			if !validMASULID(r.ID) || !validMASULID(r.Attributes.UserID) || !validMASField(r.Attributes.Email, maxMASEmailBytes) || r.Attributes.CreatedAt.IsZero() {
				return nil, fmt.Errorf("masadmin: list user emails returned an invalid email identity")
			}
			out = append(out, UserEmail{
				ID:        r.ID,
				UserID:    r.Attributes.UserID,
				Email:     r.Attributes.Email,
				CreatedAt: r.Attributes.CreatedAt,
			})
		}
		if page.Links.Next == "" {
			break
		}
		if len(page.Data) == 0 {
			return nil, fmt.Errorf("masadmin: list user emails returned a next page without data")
		}
		next := page.Data[len(page.Data)-1].ID
		if next == "" || next == after {
			return nil, fmt.Errorf("masadmin: list user emails returned a non-progressing cursor")
		}
		if _, seen := seenCursors[next]; seen {
			return nil, fmt.Errorf("masadmin: list user emails returned a cursor cycle")
		}
		seenCursors[next] = struct{}{}
		after = next
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

// GetUser returns the current authoritative state of one MAS account.
func (c *Client) GetUser(ctx context.Context, userID string) (User, error) {
	if !validMASULID(userID) {
		return User{}, fmt.Errorf("masadmin: get user: invalid user identity")
	}
	var out struct {
		Data resource[userAttrs] `json:"data"`
	}
	if err := c.get(ctx, "/api/admin/v1/users/"+url.PathEscape(userID), &out); err != nil {
		return User{}, fmt.Errorf("masadmin: get user: %w", err)
	}
	if !validMASULID(userID) || out.Data.ID != userID || !validMASUsername(out.Data.Attributes.Username) || out.Data.Attributes.CreatedAt.IsZero() {
		return User{}, fmt.Errorf("masadmin: get user response had unexpected identity")
	}
	return User{
		ID:            out.Data.ID,
		Username:      out.Data.Attributes.Username,
		CreatedAt:     out.Data.Attributes.CreatedAt,
		LockedAt:      out.Data.Attributes.LockedAt,
		DeactivatedAt: out.Data.Attributes.DeactivatedAt,
	}, nil
}

// HasUserEmail checks email presence with MAS's filtered user-emails endpoint. It intentionally
// fetches only one resource: the caller only needs presence, not the email value.
func (c *Client) HasUserEmail(ctx context.Context, userID string) (bool, error) {
	if !validMASULID(userID) {
		return false, fmt.Errorf("masadmin: check user email: invalid user identity")
	}
	query := url.Values{
		"count":        {"false"},
		"filter[user]": {userID},
		"page[first]":  {"1"},
	}
	var page paginatedResponse[emailAttrs]
	if err := c.get(ctx, "/api/admin/v1/user-emails?"+query.Encode(), &page); err != nil {
		return false, fmt.Errorf("masadmin: check user email: %w", err)
	}
	if len(page.Data) > 1 {
		return false, fmt.Errorf("masadmin: email presence response exceeded item limit")
	}
	if len(page.Data) == 0 && page.Links.Next != "" {
		return false, fmt.Errorf("masadmin: email presence response was not authoritative")
	}
	for _, resource := range page.Data {
		if !validMASULID(resource.ID) || resource.Attributes.UserID != userID || !validMASField(resource.Attributes.Email, maxMASEmailBytes) || resource.Attributes.CreatedAt.IsZero() {
			return false, fmt.Errorf("masadmin: email presence response had unexpected owner")
		}
	}
	return len(page.Data) != 0, nil
}

// LockUser locks the given MAS user (by ULID) — reversible, not a deactivation. Returns
// ErrUserNotFound if MAS reports no such user.
func (c *Client) LockUser(ctx context.Context, userID string) error {
	if !validMASULID(userID) {
		return fmt.Errorf("masadmin: lock user: invalid user identity")
	}
	attrs, err := c.lockUser(ctx, userID)
	if err != nil {
		return err
	}
	if attrs.LockedAt == nil {
		return fmt.Errorf("masadmin: lock user: response had no locked_at")
	}
	return nil
}

func (c *Client) lockUser(ctx context.Context, userID string) (userAttrs, error) {
	token, err := c.token(ctx)
	if err != nil {
		return userAttrs{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/admin/v1/users/"+url.PathEscape(userID)+"/lock", nil)
	if err != nil {
		return userAttrs{}, errors.New("masadmin: create lock request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return userAttrs{}, masadminTransportError("masadmin: lock user", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return userAttrs{}, fmt.Errorf("masadmin: lock user: %w", ErrUserNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return userAttrs{}, fmt.Errorf("masadmin: lock user: %s", describeError(resp))
	}
	var out struct {
		Data resource[userAttrs] `json:"data"`
	}
	if err := jsonbody.Decode(resp.Body, maxJSONBodyBytes, &out); err != nil {
		return userAttrs{}, fmt.Errorf("masadmin: decode lock user: %w", err)
	}
	if out.Data.ID != userID || !validMASUsername(out.Data.Attributes.Username) || out.Data.Attributes.CreatedAt.IsZero() {
		return userAttrs{}, fmt.Errorf("masadmin: lock user response had unexpected identity")
	}
	return out.Data.Attributes, nil
}

func validMASField(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

var masUsernamePattern = regexp.MustCompile(`^[0-9a-z=_+\-./]+$`)

// MAS identifies users and user-email resources with canonical 26-character ULIDs. Keeping this
// check separate from the generic field bound prevents malformed upstream identities from becoming
// Matrix IDs, lock paths, pagination cursors, or durable digest cursors.
func validMASULID(value string) bool {
	if len(value) != 26 || value[0] > '7' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := range value {
		if !strings.ContainsRune(alphabet, rune(value[i])) {
			return false
		}
	}
	return true
}

func validMASUsername(value string) bool {
	return validMASField(value, maxMASIdentifierBytes) && masUsernamePattern.MatchString(value)
}

// ValidMXID verifies the exact local Matrix identity Janitor would derive from a MAS username.
// MAS bounds the username field independently, but Matrix bounds the complete user ID; callers
// must supply the already validated deployment server name so a foreign or oversized identity is
// never used for a mutation or durable verification lookup.
func ValidMXID(username, serverName string) bool {
	return validMASUsername(username) && serverName != "" && len("@"+username+":"+serverName) <= maxMASIdentifierBytes
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
		return errors.New("masadmin: create request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return masadminTransportError("masadmin: request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrUserNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", describeError(resp))
	}
	return jsonbody.Decode(resp.Body, maxJSONBodyBytes, out)
}

func rejectRedirects(*http.Request, []*http.Request) error {
	return errors.New("MAS admin redirects are disabled")
}

func noProxyTransport() http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	transport = transport.Clone()
	transport.Proxy = nil
	transport.MaxResponseHeaderBytes = maxMASResponseHeaderBytes
	return transport
}

func masadminTransportError(prefix string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return errors.New(prefix + " failed")
}

// describeError returns only a stable status. MAS error envelopes and fallback bodies are not
// trusted diagnostic data: they may echo a client secret, bearer token, or user-provided value.
// Drain only a bounded prefix to preserve keep-alive reuse without permitting an oversized error
// response to consume memory.
func describeError(resp *http.Response) string {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
	return fmt.Sprintf("status %d", resp.StatusCode)
}
