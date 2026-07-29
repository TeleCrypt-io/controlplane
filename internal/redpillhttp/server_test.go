package redpillhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
)

type fakeProvisioner struct {
	result *agent.Provisioned
	err    error
	calls  int
}

func (f *fakeProvisioner) ProvisionAgent(ctx context.Context) (*agent.Provisioned, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func TestHandleRedpill_HappyPath(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{
		MXID:        "@abc123:telecrypt.io",
		AccessToken: "mct_token",
		DeviceID:    "AGTDEADBEEF",
		Homeserver:  "https://telecrypt.io",
	}}
	s := New(p, NewRateLimiter(5, 60, time.Minute), "https://backend.telecrypt.io/plan", "")

	req := httptest.NewRequest("POST", "/redpill", nil)
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
	if resp["access_token"] != "mct_token" {
		t.Errorf("access_token = %v, want mct_token", resp["access_token"])
	}
	if _, ok := resp["adopt_url"]; ok {
		t.Error("response must not contain adopt_url — the nonce-based adopt flow is gone")
	}
	if _, ok := resp["adopt_instructions"]; ok {
		t.Error("response must not contain adopt_instructions — the DM handshake is gone")
	}
	plan, ok := resp["plan_url"]
	if !ok {
		t.Fatal("response must contain plan_url — guidance for attaching to a paid team")
	}
	if plan != "https://backend.telecrypt.io/plan" {
		t.Errorf("plan_url = %v, want https://backend.telecrypt.io/plan", plan)
	}
}

func TestHandleRedpill_ProvisioningFails(t *testing.T) {
	p := &fakeProvisioner{err: errors.New("mas unreachable")}
	s := New(p, NewRateLimiter(5, 60, time.Minute), "https://backend.telecrypt.io/plan", "")

	req := httptest.NewRequest("POST", "/redpill", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleRedpill_RateLimited(t *testing.T) {
	p := &fakeProvisioner{result: &agent.Provisioned{MXID: "@x:telecrypt.io"}}
	s := New(p, NewRateLimiter(1, 1000, time.Minute), "https://telecrypt.io/plan", "")

	req1 := httptest.NewRequest("POST", "/redpill", nil)
	req1.Header.Set("X-Forwarded-For", "9.9.9.9")
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("first call: status = %d, want 200", w1.Code)
	}

	req2 := httptest.NewRequest("POST", "/redpill", nil)
	req2.Header.Set("X-Forwarded-For", "9.9.9.9")
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, req2)
	if w2.Code != 429 {
		t.Errorf("second call from same source: status = %d, want 429", w2.Code)
	}
	if p.calls != 1 {
		t.Errorf("provisioner should not be called once rate-limited, calls = %d", p.calls)
	}
}

func TestHandleHealth(t *testing.T) {
	s := New(&fakeProvisioner{}, NewRateLimiter(5, 60, time.Minute), "https://telecrypt.io/plan", "")

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
