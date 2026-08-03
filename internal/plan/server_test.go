package plan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeCashier struct {
	principal Principal
	requestID string
}

func (f *fakeCashier) PlanState(context.Context, Principal) (State, error) { return State{}, nil }
func (f *fakeCashier) CreateTeam(_ context.Context, p Principal, requestID string) (Team, error) {
	f.principal, f.requestID = p, requestID
	return Team{ID: "team-id"}, nil
}
func (f *fakeCashier) AttachSeat(context.Context, Principal, string, string) error {
	return errors.New("unused")
}
func (f *fakeCashier) RemoveSeat(context.Context, Principal, string, string) error {
	return errors.New("unused")
}
func (f *fakeCashier) StartCheckout(context.Context, Principal, string, int) (string, error) {
	return "", errors.New("unused")
}
func (f *fakeCashier) OpenCustomerPortal(context.Context, Principal, string) (string, error) {
	return "", errors.New("unused")
}
func (f *fakeCashier) ChangeSeatCount(context.Context, Principal, string, int) error {
	return errors.New("unused")
}
func (f *fakeCashier) ReconcileSeatCount(context.Context, Principal, string) error {
	return errors.New("unused")
}

func testServer() *Server {
	return NewServer(Config{
		ServerName:      "telecrypt.test",
		Homeserver:      "https://backend.test.telecrypt.io",
		MASBaseURL:      "http://mas:8080",
		PlanPublicURL:   "https://backend.test.telecrypt.io/plan",
		MASClientID:     "plan",
		MASClientSecret: "test-secret",
		SessionKey:      "test-session-key",
	}, nil)
}

func TestServerRendersPublicPlanLoginSurface(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /plan status = %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Fatalf("GET /plan Cache-Control = %q, want %q", got, want)
	}
	if !strings.Contains(rec.Body.String(), "/plan/login") {
		t.Fatal("GET /plan does not offer the MAS login route")
	}
}

func TestServerHealth(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /health status = %d, want %d", got, want)
	}
}

func TestPlanCommandsRequireAuthenticatedBrowserSession(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest(http.MethodPost, "/api/team", nil)
	req.Header.Set("Origin", "https://backend.test.telecrypt.io")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("unauthenticated POST /api/team status = %d, want %d", got, want)
	}
}

func TestCreateTeamUsesAuthenticatedPrincipalAndRequestID(t *testing.T) {
	cashier := &fakeCashier{}
	srv := testServer()
	srv.cashier = cashier
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:telecrypt.test")
	cookie := cookieRecorder.Result().Cookies()[0]
	requestID := "b3987ed2-51a4-4b04-b5f5-b915683d0cf5"
	req := httptest.NewRequest(http.MethodPost, "/api/team", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://backend.test.telecrypt.io")
	req.Header.Set("X-TeleCrypt-Request-ID", requestID)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusCreated; got != want {
		t.Fatalf("POST /api/team status = %d, want %d", got, want)
	}
	if got, want := cashier.principal.MXID, "@alice:telecrypt.test"; got != want {
		t.Fatalf("Cashier principal = %q, want %q", got, want)
	}
	if got, want := cashier.requestID, requestID; got != want {
		t.Fatalf("Cashier request ID = %q, want %q", got, want)
	}
}
