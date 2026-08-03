package steward

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

// OIDCClient is Plan's MAS authorization-code + PKCE client. Browser authorization uses the
// public homeserver URL; token and userinfo calls use MAS's private Compose address.
type OIDCClient struct {
	authorizeURL, tokenURL, userinfoURL, clientID, clientSecret, redirectURI string
	httpClient                                                               *http.Client
}

func NewOIDCClient(homeserver, masBaseURL, clientID, clientSecret, redirectURI string) *OIDCClient {
	homeserver, masBaseURL = strings.TrimRight(homeserver, "/"), strings.TrimRight(masBaseURL, "/")
	return &OIDCClient{authorizeURL: homeserver + "/auth/authorize", tokenURL: masBaseURL + "/oauth2/token", userinfoURL: masBaseURL + "/oauth2/userinfo", clientID: clientID, clientSecret: clientSecret, redirectURI: redirectURI, httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func NewPKCEPair() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (c *OIDCClient) AuthorizeURL(state, challenge string) string {
	v := url.Values{"response_type": {"code"}, "client_id": {c.clientID}, "redirect_uri": {c.redirectURI}, "scope": {"openid"}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return c.authorizeURL + "?" + v.Encode()
}

func (c *OIDCClient) ExchangeCode(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.redirectURI}, "code_verifier": {verifier}}
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

func (c *OIDCClient) Username(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo: unexpected status %d", resp.StatusCode)
	}
	var out struct {
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
