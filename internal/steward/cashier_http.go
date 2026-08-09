package steward

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

const (
	planAssertionAudience = "telecrypt-cashier"
	planRequestIDHeader   = "X-TeleCrypt-Request-ID"
)

// HTTPCashierClient is the sole Plan-to-Cashier transport. It is deliberately limited to the
// CashierClient interface, so public Plan code cannot gain Dodo, Synapse, or database access.
type HTTPCashierClient struct {
	baseURL    string
	privateKey ed25519.PrivateKey
	httpClient *http.Client
}

func NewHTTPCashierClient(baseURL, encodedPrivateKey string, httpClient *http.Client) (*HTTPCashierClient, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme != "http" || parsedURL.Host == "" || parsedURL.User != nil ||
		(parsedURL.Path != "" && parsedURL.Path != "/") || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("Cashier URL must be an HTTP origin")
	}
	key, err := base64.RawURLEncoding.DecodeString(encodedPrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("STEWARD_ASSERTION_PRIVATE_KEY must be a raw URL-safe base64 Ed25519 private key")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &HTTPCashierClient{baseURL: strings.TrimRight(baseURL, "/"), privateKey: ed25519.PrivateKey(key), httpClient: httpClient}, nil
}

func (c *HTTPCashierClient) PlanState(ctx context.Context, principal Principal) (PlanState, error) {
	// Cashier's private response retains its historical `team` key. Translate that wire-only
	// compatibility shape at the transport boundary so Steward's owned model remains plan-native.
	var response struct {
		LegacyTeam *Plan  `json:"team"`
		Seats      []Seat `json:"seats"`
	}
	err := c.do(ctx, principal, http.MethodGet, "/internal/v1/plan-state", uuid.NewString(), nil, &response)
	return PlanState{Plan: response.LegacyTeam, Seats: response.Seats}, err
}

// CreatePlan keeps Cashier's historical /teams path because Cashier is a separate, private
// service that is not present in this repository. The public Plan product does not expose that
// implementation term.
func (c *HTTPCashierClient) CreatePlan(ctx context.Context, p Principal, requestID string) (Plan, error) {
	var plan Plan
	err := c.do(ctx, p, http.MethodPost, "/internal/v1/teams", requestID, []byte(`{}`), &plan)
	return plan, err
}

func (c *HTTPCashierClient) AttachSeat(ctx context.Context, p Principal, requestID, mxid string) error {
	body, err := json.Marshal(struct {
		MXID string `json:"mxid"`
	}{MXID: mxid})
	if err != nil {
		return err
	}
	return c.do(ctx, p, http.MethodPost, "/internal/v1/team/seats", requestID, body, nil)
}

func (c *HTTPCashierClient) RemoveSeat(ctx context.Context, p Principal, requestID, mxid string) error {
	return c.do(ctx, p, http.MethodDelete, "/internal/v1/team/seats/"+url.PathEscape(mxid), requestID, nil, nil)
}

func (c *HTTPCashierClient) StartCheckout(ctx context.Context, p Principal, requestID string, quantity int) (string, error) {
	var response struct {
		PaymentLink string `json:"payment_link"`
	}
	body, err := json.Marshal(struct {
		Quantity int `json:"quantity"`
	}{Quantity: quantity})
	if err != nil {
		return "", err
	}
	err = c.do(ctx, p, http.MethodPost, "/internal/v1/team/checkout", requestID, body, &response)
	return response.PaymentLink, err
}

func (c *HTTPCashierClient) OpenCustomerPortal(ctx context.Context, p Principal, requestID string) (string, error) {
	var response struct {
		Link string `json:"link"`
	}
	err := c.do(ctx, p, http.MethodPost, "/internal/v1/team/portal", requestID, []byte(`{}`), &response)
	return response.Link, err
}

func (c *HTTPCashierClient) ChangeSeatCount(ctx context.Context, p Principal, requestID string, quantity int) error {
	body, err := json.Marshal(struct {
		Quantity int `json:"quantity"`
	}{Quantity: quantity})
	if err != nil {
		return err
	}
	return c.do(ctx, p, http.MethodPost, "/internal/v1/team/seat-count", requestID, body, nil)
}

func (c *HTTPCashierClient) ReconcileSeatCount(ctx context.Context, p Principal, requestID string) error {
	return c.do(ctx, p, http.MethodPost, "/internal/v1/team/seat-count/reconcile", requestID, []byte(`{}`), nil)
}

func (c *HTTPCashierClient) do(ctx context.Context, principal Principal, method, path, requestID string, body []byte, result any) error {
	if principal.MXID == "" {
		return fmt.Errorf("missing Plan principal")
	}
	if _, err := uuid.Parse(requestID); err != nil {
		return fmt.Errorf("invalid Plan request ID")
	}
	assertion, err := c.assertion(principal.MXID, method, path, requestID, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create cashier request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+assertion)
	if method != http.MethodGet {
		req.Header.Set(planRequestIDHeader, requestID)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call cashier: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		return &CashierError{StatusCode: response.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	if result != nil {
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(result); err != nil {
			return fmt.Errorf("decode cashier response: %w", err)
		}
	}
	return nil
}

type CashierError struct {
	StatusCode int
	Message    string
}

func (e *CashierError) Error() string { return fmt.Sprintf("cashier returned %d", e.StatusCode) }

func (c *HTTPCashierClient) assertion(subject, method, path, requestID string, body []byte) (string, error) {
	sum := sha256.Sum256(body)
	payload, err := json.Marshal(struct {
		Subject    string `json:"sub"`
		Audience   string `json:"aud"`
		Expires    int64  `json:"exp"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		RequestID  string `json:"request_id"`
		BodySHA256 string `json:"body_sha256"`
	}{subject, planAssertionAudience, time.Now().Add(time.Minute).Unix(), method, path, requestID, base64.RawURLEncoding.EncodeToString(sum[:])})
	if err != nil {
		return "", fmt.Errorf("marshal Plan assertion: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := header + "." + encodedPayload
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.privateKey, []byte(signingInput))), nil
}
