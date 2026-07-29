// Package masoidc is cashier's OIDC client to MAS for the Plan-tab login flow. Endpoint paths
// and the userinfo claim shape mirror the pre-rework masoidc package (authorization_code + PKCE,
// client_secret_basic). Split public/internal base URLs: authorize redirects the browser to the
// public https://telecrypt.io/auth/... URL; token exchange and userinfo are server-to-server
// against mas:8080 inside telecrypt_net.
package masoidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	authorizeURL string
	tokenURL     string
	userinfoURL  string
	clientID     string
	clientSecret string
	redirectURI  string
	httpClient   *http.Client
}

func NewClient(homeserver, masBaseURL, clientID, clientSecret, redirectURI string) *Client {
	homeserver = strings.TrimRight(homeserver, "/")
	masBaseURL = strings.TrimRight(masBaseURL, "/")
	return &Client{
		authorizeURL: homeserver + "/auth/authorize",
		tokenURL:     masBaseURL + "/oauth2/token",
		userinfoURL:  masBaseURL + "/oauth2/userinfo",
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) RedirectURI() string { return c.redirectURI }

// AuthorizeURL builds the browser-redirect URL for authorization_code + PKCE(S256).
func (c *Client) AuthorizeURL(state, codeChallenge string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", c.clientID)
	v.Set("redirect_uri", c.redirectURI)
	v.Set("scope", "openid")
	v.Set("state", state)
	v.Set("code_challenge", codeChallenge)
	v.Set("code_challenge_method", "S256")
	return c.authorizeURL + "?" + v.Encode()
}

// ExchangeCode redeems an authorization code (server-to-server, client_secret_basic + PKCE).
func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier string) (accessToken string, err error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURI)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange: unexpected status %d", resp.StatusCode)
	}

	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("token exchange response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token exchange: empty access_token")
	}
	return out.AccessToken, nil
}

// Username calls userinfo and returns the MAS localpart.
func (c *Client) Username(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo: unexpected status %d", resp.StatusCode)
	}

	var out struct {
		Sub      string `json:"sub"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("userinfo response: %w", err)
	}
	if out.Username == "" {
		return "", fmt.Errorf("userinfo: empty username")
	}
	return out.Username, nil
}

// NewPKCEPair returns a verifier/challenge pair for S256 PKCE.
func NewPKCEPair() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
