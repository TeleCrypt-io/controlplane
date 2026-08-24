package registrationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
)

type fakeProvisioner struct {
	result *agent.Provisioned
	err    error
	calls  int
}

type contextProvisioner struct{ hasDeadline bool }

func (p *contextProvisioner) ProvisionAgent(ctx context.Context) (*agent.Provisioned, error) {
	_, p.hasDeadline = ctx.Deadline()
	return &agent.Provisioned{}, nil
}

func TestHandleRegistration_BoundsProvisioningTime(t *testing.T) {
	p := &contextProvisioner{}
	s := New(p, NewRateLimiter(60, time.Minute), "https://telecrypt.io/plan")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/agents", nil))
	if !p.hasDeadline {
		t.Fatal("ProvisionAgent did not receive a bounded context")
	}
}

func TestHandleRegistration_DoesNotLogProvisioningError(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	secret := "generated-password-must-not-appear"
	s := New(&fakeProvisioner{err: errors.New(secret)}, NewRateLimiter(60, time.Minute), "https://telecrypt.io/plan")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/agents", nil))
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("provisioning log leaked secret: %s", logs.String())
	}
}

func (f *fakeProvisioner) ProvisionAgent(ctx context.Context) (*agent.Provisioned, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func TestHandleRegistration_HappyPath(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{
		MXID:               "@abc123:telecrypt.io",
		Password:           "generated-password",
		AccessToken:        "oauth-access",
		RefreshToken:       "oauth-refresh",
		ExpiresIn:          3600,
		DeviceID:           "AGTDEADBEEF",
		Homeserver:         "https://telecrypt.io",
		OAuthIssuer:        "https://telecrypt.io/auth",
		OAuthClientID:      "dynamic-client",
		OAuthTokenEndpoint: "https://telecrypt.io/auth/oauth2/token",
	}}
	s := New(p, NewRateLimiter(60, time.Minute), "https://backend.telecrypt.io/plan")

	req := httptest.NewRequest("POST", "/agents", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["mxid"] != "@abc123:telecrypt.io" {
		t.Errorf("mxid = %v, want @abc123:telecrypt.io", resp["mxid"])
	}
	if resp["password"] != "generated-password" || resp["access_token"] != "oauth-access" || resp["refresh_token"] != "oauth-refresh" || resp["expires_in"] != float64(3600) {
		t.Errorf("credential response = %v, want complete refreshable OAuth credentials", resp)
	}
	if resp["issuer"] != "https://telecrypt.io/auth" || resp["client_id"] != "dynamic-client" || resp["token_endpoint"] != "https://telecrypt.io/auth/oauth2/token" {
		t.Errorf("OAuth refresh metadata = %v", resp)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
	plan, ok := resp["plan_url"]
	if !ok {
		t.Fatal("response must contain plan_url — guidance for attaching to a paid plan")
	}
	if plan != "https://backend.telecrypt.io/plan" {
		t.Errorf("plan_url = %v, want https://backend.telecrypt.io/plan", plan)
	}
}

func TestHandleRegistration_RejectsNonEmptyBody(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{MXID: "@abc123:telecrypt.io"}}
	s := New(p, NewRateLimiter(60, time.Minute), "https://backend.telecrypt.io/plan")
	req := httptest.NewRequest("POST", "/agents", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("non-empty body status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if p.calls != 0 {
		t.Fatalf("provisioner calls = %d, want none for non-empty body", p.calls)
	}
}

func TestHandleRegistration_ProvisioningFails(t *testing.T) {
	p := &fakeProvisioner{err: errors.New("mas unreachable")}
	s := New(p, NewRateLimiter(60, time.Minute), "https://backend.telecrypt.io/plan")

	req := httptest.NewRequest("POST", "/agents", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
}

func TestHandleRegistration_RateLimited(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{MXID: "@x:telecrypt.io"}}
	s := New(p, NewRateLimiter(1, time.Minute), "https://telecrypt.io/plan")

	req1 := httptest.NewRequest("POST", "/agents", nil)
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("first call: status = %d, want 200", w1.Code)
	}

	req2 := httptest.NewRequest("POST", "/agents", nil)
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)
	if w2.Code != 429 {
		t.Errorf("second global call: status = %d, want 429", w2.Code)
	}
	if p.calls != 1 {
		t.Errorf("provisioner should not be called once rate-limited, calls = %d", p.calls)
	}
}
