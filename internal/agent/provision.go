// Package agent contains the credential-free Redpill client for the private agent issuer.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const issuerAudience = "telecrypt-agent-issuer"

type Provisioned struct {
	MXID        string `json:"mxid"`
	AccessToken string `json:"access_token"`
	DeviceID    string `json:"device_id"`
	Homeserver  string `json:"homeserver"`
}

// Provisioner signs one narrowly-scoped request to the private issuer. It has no MAS credential.
type Provisioner struct {
	baseURL    string
	privateKey ed25519.PrivateKey
	httpClient *http.Client
}

func NewProvisioner(baseURL, encodedPrivateKey string, httpClient *http.Client) (*Provisioner, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("agent issuer URL must be a private HTTP origin")
	}
	key, err := base64.RawURLEncoding.DecodeString(encodedPrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("REDPILL_ASSERTION_PRIVATE_KEY must be a raw URL-safe base64 Ed25519 private key")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Provisioner{strings.TrimRight(baseURL, "/"), ed25519.PrivateKey(key), httpClient}, nil
}

func (p *Provisioner) ProvisionAgent(ctx context.Context) (*Provisioned, error) {
	const path = "/internal/v1/agents"
	body := []byte(`{}`)
	requestID := uuid.NewString()
	assertion, err := p.assertion(http.MethodPost, path, requestID, body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create issuer request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+assertion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TeleCrypt-Request-ID", requestID)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call agent issuer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("agent issuer returned %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	var result Provisioned
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode agent issuer response: %w", err)
	}
	if result.MXID == "" || result.AccessToken == "" || result.DeviceID == "" || result.Homeserver == "" {
		return nil, fmt.Errorf("agent issuer returned an incomplete account")
	}
	return &result, nil
}

func (p *Provisioner) assertion(method, path, requestID string, body []byte) (string, error) {
	sum := sha256.Sum256(body)
	payload, err := json.Marshal(struct {
		Audience   string `json:"aud"`
		Expires    int64  `json:"exp"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		RequestID  string `json:"request_id"`
		BodySHA256 string `json:"body_sha256"`
	}{issuerAudience, time.Now().Add(time.Minute).Unix(), method, path, requestID, base64.RawURLEncoding.EncodeToString(sum[:])})
	if err != nil {
		return "", fmt.Errorf("marshal issuer assertion: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := header + "." + encodedPayload
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.privateKey, []byte(input))), nil
}
