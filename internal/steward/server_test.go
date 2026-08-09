package steward

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
	state     State
}

func (f *fakeCashier) PlanState(context.Context, Principal) (State, error) { return f.state, nil }
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
	body := rec.Body.String()
	if !strings.Contains(body, "/plan/login") {
		t.Fatal("GET /plan does not offer the MAS login route")
	}
	for _, marker := range []string{
		"Create a TeleCrypt account",
		"/plan/assets/logo-mark.png",
		"/plan/assets/product.css",
		"/plan/assets/plan.css",
		"/plan/assets/plan.js",
		"Sign-in is handled by your TeleCrypt account.",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("public Plan page is missing %q", marker)
		}
	}
}

func TestServerRendersPersistentSandboxBanner(t *testing.T) {
	srv := testServer()
	srv.cfg.BillingEnv = "test"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plan", nil))
	if !strings.Contains(rec.Body.String(), "TEST / SANDBOX") {
		t.Fatal("GET /plan does not visibly identify the test billing environment")
	}
}

func TestPlanAssetsAreLocalAndCarryCommandContract(t *testing.T) {
	srv := testServer()

	for _, asset := range []struct {
		path        string
		contentType string
		marker      string
	}{
		{"/plan/assets/product.css", "text/css; charset=utf-8", "--surface: #ffffff"},
		{"/plan/assets/plan.css", "text/css; charset=utf-8", "Plan-specific layout"},
		{"/plan/assets/plan.js", "text/javascript; charset=utf-8", "X-TeleCrypt-Request-ID"},
		{"/plan/assets/logo-mark.png", "image/png", ""},
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, asset.path, nil))
		if got, want := rec.Code, http.StatusOK; got != want {
			t.Errorf("GET %s status = %d, want %d", asset.path, got, want)
		}
		if got, want := rec.Header().Get("Content-Type"), asset.contentType; got != want {
			t.Errorf("GET %s Content-Type = %q, want %q", asset.path, got, want)
		}
		if asset.marker != "" && !strings.Contains(rec.Body.String(), asset.marker) {
			t.Errorf("GET %s is missing %q", asset.path, asset.marker)
		}
	}
}

func TestServerRendersTeamPlanControlsForEachSubscriptionState(t *testing.T) {
	tests := []struct {
		name    string
		team    *Team
		seats   []Seat
		want    []string
		notWant []string
	}{
		{
			name:  "checkout",
			team:  &Team{SubscriptionStatus: "none", PaidSeats: 1, HasBillingAccount: true},
			seats: []Seat{{MXID: "@member:telecrypt.test"}},
			want: []string{
				"Start checkout", "Manage subscription, card, invoices, or cancellation",
				"id=\"add-seat\"", "data-mxid=\"@member:telecrypt.test\"",
			},
		},
		{
			name:    "active subscription",
			team:    &Team{SubscriptionStatus: "active", PaidSeats: 3},
			want:    []string{"Update paid seats", "value=\"3\"", "No seats attached yet."},
			notWant: []string{"Start checkout"},
		},
		{
			name:    "pending checkout",
			team:    &Team{SubscriptionStatus: "pending", PaidSeats: 2},
			want:    []string{"Checkout is in progress. Your plan updates after payment is confirmed."},
			notWant: []string{"Start checkout", "Update paid seats"},
		},
		{
			name:    "no team",
			want:    []string{"Create your team", "Create team"},
			notWant: []string{"id=\"add-seat\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := renderAuthenticatedPlan(t, State{Team: tt.team, Seats: tt.seats})
			for _, marker := range tt.want {
				if !strings.Contains(body, marker) {
					t.Errorf("rendered Plan page is missing %q", marker)
				}
			}
			for _, marker := range tt.notWant {
				if strings.Contains(body, marker) {
					t.Errorf("rendered Plan page unexpectedly contains %q", marker)
				}
			}
		})
	}
}

func renderAuthenticatedPlan(t *testing.T, state State) string {
	t.Helper()
	srv := testServer()
	srv.cashier = &fakeCashier{state: state}
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:telecrypt.test")
	cookie := cookieRecorder.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /plan status = %d, want %d; body: %s", got, want, rec.Body.String())
	}
	return rec.Body.String()
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
