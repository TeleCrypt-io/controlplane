package steward

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeCashier struct {
	principal Principal
	requestID string
	state     PlanState
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (f *fakeCashier) PlanState(context.Context, Principal) (PlanState, error) { return f.state, nil }
func (f *fakeCashier) CreatePlan(_ context.Context, p Principal, requestID string) (Plan, error) {
	f.principal, f.requestID = p, requestID
	return Plan{ID: "plan-id"}, nil
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
	if got := rec.Header().Get("Content-Security-Policy"); got != planContentSecurityPolicy {
		t.Fatalf("GET /plan Content-Security-Policy = %q, want %q", got, planContentSecurityPolicy)
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

func TestValidateLocalpartMatchesMatrixUserLocalpartRules(t *testing.T) {
	for _, tt := range []struct {
		localpart string
		valid     bool
	}{
		{localpart: "alice", valid: true},
		{localpart: "user_name-1.2/3=4", valid: true},
		{localpart: "", valid: false},
		{localpart: "Alice", valid: false},
		{localpart: "alice:remote", valid: false},
		{localpart: "alice@example", valid: false},
	} {
		t.Run(tt.localpart, func(t *testing.T) {
			if got := validateLocalpart(tt.localpart); got != tt.valid {
				t.Fatalf("validateLocalpart(%q) = %t, want %t", tt.localpart, got, tt.valid)
			}
		})
	}
}

func TestCallbackRejectsInvalidProviderUsername(t *testing.T) {
	srv := testServer()
	srv.oidc.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"access_token":"token"}`
		if req.URL.Path != "/oauth2/token" {
			body = `{"username":"invalid:username"}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	cookies := httptest.NewRecorder()
	setOAuthCookies(cookies, "state", "verifier")
	req := httptest.NewRequest(http.MethodGet, "/plan/callback?state=state&code=code", nil)
	for _, cookie := range cookies.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusBadGateway; got != want {
		t.Fatalf("callback status = %d, want %d", got, want)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			t.Fatal("callback issued a session for an invalid provider username")
		}
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

func TestPlanTemplateHasNoInlineScriptHandlers(t *testing.T) {
	for _, forbidden := range []string{"onclick=", "onsubmit=", "javascript:"} {
		if strings.Contains(strings.ToLower(planHTML), forbidden) {
			t.Fatalf("Plan template contains CSP-incompatible inline script marker %q", forbidden)
		}
	}
}

func TestServerRendersPlanControlsForEachSubscriptionState(t *testing.T) {
	tests := []struct {
		name    string
		plan    *Plan
		seats   []Seat
		want    []string
		notWant []string
	}{
		{
			name:  "checkout",
			plan:  &Plan{SubscriptionStatus: "none", PaidSeats: 1, HasBillingAccount: true},
			seats: []Seat{{MXID: "@member:telecrypt.test"}},
			want: []string{
				"Start checkout", "15 EUR per seat", "Manage subscription, card, invoices, or cancellation",
				"id=\"add-seat\"", "data-mxid=\"@member:telecrypt.test\"",
			},
		},
		{
			name:    "active subscription",
			plan:    &Plan{SubscriptionStatus: "active", PaidSeats: 3},
			want:    []string{"Update paid seats", "15 EUR per seat", "value=\"3\"", "No seats attached yet."},
			notWant: []string{"Start checkout"},
		},
		{
			name:    "pending checkout",
			plan:    &Plan{SubscriptionStatus: "pending", PaidSeats: 2},
			want:    []string{"Checkout is in progress. Your plan updates after payment is confirmed."},
			notWant: []string{"Start checkout", "Update paid seats"},
		},
		{
			name:    "no plan",
			want:    []string{"Set up your plan", "Set up plan", "Add the Matrix accounts you want covered"},
			notWant: []string{"id=\"add-seat\"", "<h1 id=\"plan-title\">Your Plan</h1>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := renderAuthenticatedPlan(t, PlanState{Plan: tt.plan, Seats: tt.seats})
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

func renderAuthenticatedPlan(t *testing.T, state PlanState) string {
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
	for _, command := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/plan"},
		{http.MethodPost, "/api/plan/seats"},
		{http.MethodDelete, "/api/plan/seats/@member:telecrypt.test"},
		{http.MethodPost, "/api/plan/checkout"},
		{http.MethodPost, "/api/plan/portal"},
		{http.MethodPost, "/api/plan/seat-count"},
		{http.MethodPost, "/api/plan/seat-count/reconcile"},
		{http.MethodPost, "/api/plan/downgrade-request"},
		{http.MethodPost, "/api/team"},
		{http.MethodPost, "/api/team/seats"},
		{http.MethodDelete, "/api/team/seats/@member:telecrypt.test"},
		{http.MethodPost, "/api/team/checkout"},
		{http.MethodPost, "/api/team/portal"},
		{http.MethodPost, "/api/team/seat-count"},
		{http.MethodPost, "/api/team/seat-count/reconcile"},
		{http.MethodPost, "/api/team/downgrade-request"},
	} {
		srv := testServer()
		req := httptest.NewRequest(command.method, command.path, nil)
		req.Header.Set("Origin", "https://backend.test.telecrypt.io")
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)

		if got, want := rec.Code, http.StatusUnauthorized; got != want {
			t.Errorf("unauthenticated %s %s status = %d, want %d", command.method, command.path, got, want)
		}
	}
}

func TestCreatePlanUsesAuthenticatedPrincipalAndRequestID(t *testing.T) {
	cashier := &fakeCashier{}
	srv := testServer()
	srv.cashier = cashier
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:telecrypt.test")
	cookie := cookieRecorder.Result().Cookies()[0]
	requestID := "b3987ed2-51a4-4b04-b5f5-b915683d0cf5"
	req := httptest.NewRequest(http.MethodPost, "/api/plan", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://backend.test.telecrypt.io")
	req.Header.Set("X-TeleCrypt-Request-ID", requestID)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusCreated; got != want {
		t.Fatalf("POST /api/plan status = %d, want %d", got, want)
	}
	if got, want := cashier.principal.MXID, "@alice:telecrypt.test"; got != want {
		t.Fatalf("Cashier principal = %q, want %q", got, want)
	}
	if got, want := cashier.requestID, requestID; got != want {
		t.Fatalf("Cashier request ID = %q, want %q", got, want)
	}
	if !strings.Contains(rec.Body.String(), `"plan_id":"plan-id"`) {
		t.Fatalf("POST /api/plan response = %s, want plan_id", rec.Body.String())
	}
}

func TestLegacyTeamCreateRouteRemainsCompatible(t *testing.T) {
	cashier := &fakeCashier{}
	srv := testServer()
	srv.cashier = cashier
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:telecrypt.test")
	cookie := cookieRecorder.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodPost, "/api/team", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://backend.test.telecrypt.io")
	req.Header.Set("X-TeleCrypt-Request-ID", "b3987ed2-51a4-4b04-b5f5-b915683d0cf5")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusCreated; got != want {
		t.Fatalf("POST /api/team status = %d, want %d", got, want)
	}
	if !strings.Contains(rec.Body.String(), `"team_id":"plan-id"`) {
		t.Fatalf("POST /api/team response = %s, want legacy team_id", rec.Body.String())
	}
}

func TestPlanCommandsRejectUnsafeRequestBodies(t *testing.T) {
	for _, tt := range []struct {
		name, path, body string
	}{
		{"unknown field", "/api/plan/seats", `{"mxid":"@member:telecrypt.test","unexpected":true}`},
		{"trailing JSON", "/api/plan/seat-count", `{"quantity":1}{"quantity":2}`},
		{"oversized JSON", "/api/plan/seats", `{"mxid":"@` + strings.Repeat("a", maxPlanJSONBodyBytes) + `:telecrypt.test"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServer()
			srv.cashier = &fakeCashier{}
			req := authenticatedPlanRequest(t, srv, http.MethodPost, tt.path, tt.body)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if got, want := rec.Code, http.StatusBadRequest; got != want {
				t.Fatalf("%s status = %d, want %d", tt.path, got, want)
			}
		})
	}
}

func TestDeleteSeatRejectsNonLocalMXID(t *testing.T) {
	srv := testServer()
	srv.cashier = &fakeCashier{}
	req := authenticatedPlanRequest(t, srv, http.MethodDelete, "/api/plan/seats/@member:elsewhere.test", "")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if got, want := rec.Code, http.StatusBadRequest; got != want {
		t.Fatalf("DELETE remote MXID status = %d, want %d", got, want)
	}
}

// errorCashier returns a CashierError carrying the provider's exact message and status so the
// tests prove the Plan boundary surfaces Cashier's actionable rejection text instead of a
// generic failure.
type errorCashier struct {
	status  int
	message string
}

func (c *errorCashier) PlanState(_ context.Context, _ Principal) (PlanState, error) {
	return PlanState{}, &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) CreatePlan(_ context.Context, _ Principal, _ string) (Plan, error) {
	return Plan{}, &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) AttachSeat(_ context.Context, _ Principal, _ string, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) RemoveSeat(_ context.Context, _ Principal, _ string, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) StartCheckout(_ context.Context, _ Principal, _ string, _ int) (string, error) {
	return "", &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) OpenCustomerPortal(_ context.Context, _ Principal, _ string) (string, error) {
	return "", &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) ChangeSeatCount(_ context.Context, _ Principal, _ string, _ int) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}
func (c *errorCashier) ReconcileSeatCount(_ context.Context, _ Principal, _ string) error {
	return &CashierError{StatusCode: c.status, Message: c.message}
}

func TestCashierRejectionMessagesPropagateToPlanBoundary(t *testing.T) {
	const message = "remove 1 seat(s) before lowering to 1 paid seats"
	for _, tt := range []struct {
		name, method, path, body string
	}{
		{"seat-count", http.MethodPost, "/api/plan/seat-count", `{"quantity":1}`},
		{"attach", http.MethodPost, "/api/plan/seats", `{"mxid":"@bot:telecrypt.test"}`},
		{"remove", http.MethodDelete, "/api/plan/seats/@bot:telecrypt.test", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServer()
			srv.cashier = &errorCashier{status: http.StatusConflict, message: message}
			req := authenticatedPlanRequest(t, srv, tt.method, tt.path, tt.body)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if got, want := rec.Code, http.StatusConflict; got != want {
				t.Fatalf("%s status = %d, want %d", tt.name, got, want)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != message {
				t.Fatalf("%s body = %q, want %q", tt.name, got, message)
			}
		})
	}
}

func authenticatedPlanRequest(t *testing.T, srv *Server, method, path, body string) *http.Request {
	t.Helper()
	cookieRecorder := httptest.NewRecorder()
	srv.session.Set(cookieRecorder, "@alice:telecrypt.test")
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(cookieRecorder.Result().Cookies()[0])
	req.Header.Set("Origin", "https://backend.test.telecrypt.io")
	req.Header.Set("X-TeleCrypt-Request-ID", "b3987ed2-51a4-4b04-b5f5-b915683d0cf5")
	return req
}
