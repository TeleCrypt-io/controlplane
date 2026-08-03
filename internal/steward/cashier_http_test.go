package steward

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPCashierClientSignsExactCommand(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/teams" {
			http.Error(w, "wrong route", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "{}" {
			http.Error(w, "wrong body", http.StatusBadRequest)
			return
		}
		claims := verifyPlanJWS(t, r.Header.Get("Authorization"), public)
		if claims.Subject != "@alice:telecrypt.io" || claims.Audience != planAssertionAudience ||
			claims.Method != r.Method || claims.Path != r.URL.Path ||
			claims.RequestID != "b3987ed2-51a4-4b04-b5f5-b915683d0cf5" {
			http.Error(w, "wrong claims", http.StatusUnauthorized)
			return
		}
		sum := sha256.Sum256(body)
		if claims.BodySHA256 != base64.RawURLEncoding.EncodeToString(sum[:]) || r.Header.Get(planRequestIDHeader) != claims.RequestID {
			http.Error(w, "unbound request", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"team-id","subscription_status":"none","paid_seats":0,"checkout_active":false,"has_billing_account":false}`))
	}))
	defer server.Close()

	client, err := NewHTTPCashierClient(server.URL, base64.RawURLEncoding.EncodeToString(private), server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	team, err := client.CreateTeam(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if team.ID != "team-id" {
		t.Fatalf("team ID = %q, want team-id", team.ID)
	}
}

func TestHTTPCashierClientReturnsBusinessStatus(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no paid seats available", http.StatusConflict)
	}))
	defer server.Close()
	client, err := NewHTTPCashierClient(server.URL, base64.RawURLEncoding.EncodeToString(private), server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	err = client.AttachSeat(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5", "@bot:telecrypt.io")
	var cashierError *CashierError
	if !errors.As(err, &cashierError) || cashierError.StatusCode != http.StatusConflict {
		t.Fatalf("AttachSeat error = %#v, want CashierError 409", err)
	}
}

func verifyPlanJWS(t *testing.T, authorization string, public ed25519.PublicKey) planAssertion {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(parts) != 3 || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), mustDecode(t, parts[2])) {
		t.Fatal("Cashier Authorization is not a valid EdDSA JWS")
	}
	var claims planAssertion
	if err := json.Unmarshal(mustDecode(t, parts[1]), &claims); err != nil {
		t.Fatalf("decode JWS claims: %v", err)
	}
	return claims
}

type planAssertion struct {
	Subject string `json:"sub"`
	Audience string `json:"aud"`
	Method string `json:"method"`
	Path string `json:"path"`
	RequestID string `json:"request_id"`
	BodySHA256 string `json:"body_sha256"`
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil { t.Fatalf("base64 decode: %v", err) }
	return decoded
}
