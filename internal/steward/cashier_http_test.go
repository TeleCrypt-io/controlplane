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

func TestHTTPCashierClientPreservesPrivatePlanCreationProtocol(t *testing.T) {
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
	plan, err := client.CreatePlan(t.Context(), Principal{MXID: "@alice:telecrypt.io"}, "b3987ed2-51a4-4b04-b5f5-b915683d0cf5")
	if err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if plan.ID != "team-id" {
		t.Fatalf("plan ID = %q, want team-id", plan.ID)
	}
}

func TestHTTPCashierClientMapsPrivateTeamStateToPlanModel(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v1/plan-state" {
			http.Error(w, "wrong route", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"team":{"id":"legacy-team-id","subscription_status":"active","paid_seats":2},"seats":[{"mxid":"@alice:telecrypt.io"}]}`))
	}))
	defer server.Close()

	client, err := NewHTTPCashierClient(server.URL, base64.RawURLEncoding.EncodeToString(private), server.Client())
	if err != nil {
		t.Fatalf("new HTTP Cashier client: %v", err)
	}
	state, err := client.PlanState(t.Context(), Principal{MXID: "@alice:telecrypt.io"})
	if err != nil {
		t.Fatalf("PlanState: %v", err)
	}
	if state.Plan == nil || state.Plan.ID != "legacy-team-id" || state.Plan.PaidSeats != 2 {
		t.Fatalf("PlanState plan = %#v, want mapped private team", state.Plan)
	}
	if len(state.Seats) != 1 || state.Seats[0].MXID != "@alice:telecrypt.io" {
		t.Fatalf("PlanState seats = %#v", state.Seats)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal PlanState: %v", err)
	}
	if strings.Contains(string(encoded), `"team"`) || !strings.Contains(string(encoded), `"plan"`) {
		t.Fatalf("owned PlanState JSON = %s, want plan key and no team key", encoded)
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
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	RequestID  string `json:"request_id"`
	BodySHA256 string `json:"body_sha256"`
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return decoded
}
