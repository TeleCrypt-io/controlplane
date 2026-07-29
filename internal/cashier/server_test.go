package cashier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dodo "github.com/dodopayments/dodopayments-go"
	"github.com/dodopayments/dodopayments-go/option"
	"github.com/google/uuid"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
)

func TestHandlePlan_Unauthenticated(t *testing.T) {
	cfg := &config.CashierConfig{
		PlanPublicURL: "https://backend.telecrypt.io/plan",
		Homeserver:    "https://backend.telecrypt.io",
		ServerName:    "telecrypt.io",
	}
	srv := NewServer(cfg, nil, nil, nil, NewSession("test-key"), nil)

	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, "Create a TeleCrypt account") || !contains(body, ">log in</a>") {
		t.Fatalf("expected registration and login prompts, got: %s", body)
	}
	if !contains(body, `href="https://backend.telecrypt.io/auth/register"`) {
		t.Fatalf("expected MAS registration link, got: %s", body)
	}
	if contains(body, "4242 4242 4242 4242") {
		t.Fatal("production/default Plan page exposed sandbox card instructions")
	}
}

func TestHandlePlan_TestModeBannerAndCard(t *testing.T) {
	cfg := &config.CashierConfig{
		TelecryptEnv:  "test",
		PlanPublicURL: "https://plan.test.telecrypt.io/plan",
		Homeserver:    "https://plan.test.telecrypt.io",
		ServerName:    "telecrypt.io",
	}
	srv := NewServer(cfg, nil, nil, nil, NewSession("test-key"), nil)

	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"TEST / SANDBOX", "4242 4242 4242 4242", "06/32", "CVV"} {
		if !contains(body, want) {
			t.Fatalf("test Plan page missing %q: %s", want, body)
		}
	}
}

func TestHandlePlan_AuthenticatedTeamHasCompleteSeatControls(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	customerID := "cus_test"
	store.teams[teamID] = db.Team{
		ID:                 teamID,
		AdminMXID:          "@admin:telecrypt.io",
		DodoCustomerID:     &customerID,
		SubscriptionStatus: "active",
		PaidSeats:          2,
	}
	store.seats[teamID] = []db.Seat{{MXID: "@bot:telecrypt.io", TeamID: teamID}}
	session := NewSession("test-key")
	cfg := &config.CashierConfig{
		TelecryptEnv:  "test",
		PlanPublicURL: "https://plan.test.telecrypt.io/plan",
		Homeserver:    "https://plan.test.telecrypt.io",
		ServerName:    "telecrypt.io",
	}
	srv := NewServer(cfg, store, nil, nil, session, nil)
	req := authenticatedRequest(t, session, http.MethodGet, "/plan", "")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"@bot:telecrypt.io",
		`onclick="removeSeat(this.dataset.mxid)"`,
		"Update paid seats",
		"/api/team/seat-count",
		"Manage subscription, card, invoices, or cancellation",
	} {
		if !contains(body, want) {
			t.Fatalf("authenticated Plan page missing %q: %s", want, body)
		}
	}
}

func TestAPIRequiresSession(t *testing.T) {
	cfg := &config.CashierConfig{PlanPublicURL: "https://telecrypt.io/plan", ServerName: "telecrypt.io"}
	srv := NewServer(cfg, nil, nil, nil, NewSession("test-key"), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/team", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func authenticatedRequest(t *testing.T, session *Session, method, target, origin string) *http.Request {
	t.Helper()
	cookieRec := httptest.NewRecorder()
	session.Set(cookieRec, "@admin:telecrypt.io")
	cookies := cookieRec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("session cookie count = %d, want 1", len(cookies))
	}
	req := httptest.NewRequest(method, target, nil)
	req.AddCookie(cookies[0])
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func TestStateChangingAPIsRequirePlanOrigin(t *testing.T) {
	tests := []struct {
		name, origin string
		want         int
	}{
		{"missing origin", "", http.StatusForbidden},
		{"cross origin", "https://attacker.example", http.StatusForbidden},
		{"plan origin", "https://backend.telecrypt.io", http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeTeamStore()
			session := NewSession("test-key")
			srv := NewServer(&config.CashierConfig{
				PlanPublicURL: "https://backend.telecrypt.io/plan",
				ServerName:    "telecrypt.io",
			}, store, nil, nil, session, nil)
			req := authenticatedRequest(t, session, http.MethodPost, "/api/team", tt.origin)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want != http.StatusCreated && len(store.teams) != 0 {
				t.Fatal("rejected request changed team state")
			}
		})
	}
}

func TestValidateLocalMXID(t *testing.T) {
	tests := []struct {
		mxid string
		want bool
	}{
		{"@bot_1:telecrypt.io", true},
		{"@bot/one:telecrypt.io", true},
		{"bot:telecrypt.io", false},
		{"@bot:elsewhere.example", false},
		{"@bot?query:telecrypt.io", false},
		{"@bot:telecrypt.io/path", false},
	}
	for _, tt := range tests {
		if got := validateLocalMXID(tt.mxid, "telecrypt.io"); got != tt.want {
			t.Errorf("validateLocalMXID(%q) = %v, want %v", tt.mxid, got, tt.want)
		}
	}
}

func TestHandleAddSeatRejectsNonexistentLocalAccountWithoutConsumingCapacity(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	store.teams[teamID] = db.Team{
		ID:                 teamID,
		AdminMXID:          "@admin:telecrypt.io",
		SubscriptionStatus: "active",
		PaidSeats:          1,
	}
	exists := false
	srv := &Server{
		cfg:        &config.CashierConfig{ServerName: "telecrypt.io"},
		store:      store,
		reconciler: NewReconciler(store, &fakeSynapse{userExists: &exists}),
	}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seats", strings.NewReader(`{"mxid":"@missing:telecrypt.io"}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()

	srv.handleAddSeat(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(store.seats[teamID]) != 0 {
		t.Fatalf("nonexistent account consumed a seat: %v", store.seats[teamID])
	}
}

func TestHandleAddSeatRejectsRemoteAccountBeforeSynapseLookup(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	store.teams[teamID] = db.Team{
		ID:                 teamID,
		AdminMXID:          "@admin:telecrypt.io",
		SubscriptionStatus: "active",
		PaidSeats:          1,
	}
	srv := &Server{cfg: &config.CashierConfig{ServerName: "telecrypt.io"}, store: store}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seats", strings.NewReader(`{"mxid":"@remote:elsewhere.example"}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()

	srv.handleAddSeat(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if len(store.seats[teamID]) != 0 {
		t.Fatalf("remote account consumed a seat: %v", store.seats[teamID])
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// fakeTeamStore is deliberately small/in-memory but implements both cashier store interfaces so
// handler tests exercise the exact ordering between a Synapse update and local state mutation.
type fakeTeamStore struct {
	teams   map[uuid.UUID]db.Team
	seats   map[uuid.UUID][]db.Seat
	manual  map[string]bool
	billing map[string]bool
}

func newFakeTeamStore() *fakeTeamStore {
	return &fakeTeamStore{
		teams:   map[uuid.UUID]db.Team{},
		seats:   map[uuid.UUID][]db.Seat{},
		manual:  map[string]bool{},
		billing: map[string]bool{},
	}
}

func (f *fakeTeamStore) CreateTeam(_ context.Context, adminMXID string) (db.Team, error) {
	id := uuid.New()
	t := db.Team{ID: id, AdminMXID: adminMXID}
	f.teams[id] = t
	return t, nil
}

func (f *fakeTeamStore) GetTeamByAdminMXID(_ context.Context, adminMXID string) (db.Team, bool, error) {
	for _, t := range f.teams {
		if t.AdminMXID == adminMXID {
			return t, true, nil
		}
	}
	return db.Team{}, false, nil
}

func (f *fakeTeamStore) GetTeamByID(_ context.Context, id uuid.UUID) (db.Team, error) {
	t, ok := f.teams[id]
	if !ok {
		return db.Team{}, errTeamNotFound
	}
	return t, nil
}

func (f *fakeTeamStore) GetTeamByDodoSubscriptionID(_ context.Context, subID string) (db.Team, bool, error) {
	for _, t := range f.teams {
		if t.DodoSubscriptionID != nil && *t.DodoSubscriptionID == subID {
			return t, true, nil
		}
	}
	return db.Team{}, false, nil
}

func (f *fakeTeamStore) GetSubscriptionBinding(_ context.Context, subID string) (db.SubscriptionBinding, bool, error) {
	for _, t := range f.teams {
		if t.DodoSubscriptionID != nil && *t.DodoSubscriptionID == subID {
			return db.SubscriptionBinding{TeamID: t.ID, IsCurrent: true}, true, nil
		}
	}
	return db.SubscriptionBinding{}, false, nil
}

func (f *fakeTeamStore) InsertSeat(_ context.Context, teamID uuid.UUID, mxid string) error {
	f.seats[teamID] = append(f.seats[teamID], db.Seat{MXID: mxid, TeamID: teamID})
	return nil
}

func (f *fakeTeamStore) AttachSeat(ctx context.Context, teamID uuid.UUID, mxid string) error {
	count, err := f.CountSeatsForTeam(ctx, teamID)
	if err != nil {
		return err
	}
	capacity := f.teams[teamID].PaidSeats
	if pending := f.teams[teamID].PendingPaidSeats; pending != nil && *pending < capacity {
		capacity = *pending
	}
	if count >= capacity {
		return db.ErrSeatCapacityReached
	}
	return f.InsertSeat(ctx, teamID, mxid)
}

func (f *fakeTeamStore) DeleteSeat(_ context.Context, mxid string) error {
	for id, seats := range f.seats {
		for i, seat := range seats {
			if seat.MXID == mxid {
				f.seats[id] = append(seats[:i:i], seats[i+1:]...)
				return nil
			}
		}
	}
	return nil
}

func (f *fakeTeamStore) CountSeatsForTeam(_ context.Context, teamID uuid.UUID) (int, error) {
	return len(f.seats[teamID]), nil
}

func (f *fakeTeamStore) ListSeatsForTeam(_ context.Context, teamID uuid.UUID) ([]db.Seat, error) {
	return append([]db.Seat(nil), f.seats[teamID]...), nil
}

func (f *fakeTeamStore) UpdateTeamSubscription(_ context.Context, teamID uuid.UUID, status string, paidSeats int, customerID, subID *string) error {
	t := f.teams[teamID]
	t.SubscriptionStatus = status
	t.PaidSeats = paidSeats
	if customerID != nil {
		t.DodoCustomerID = customerID
	}
	if subID != nil {
		t.DodoSubscriptionID = subID
	}
	f.teams[teamID] = t
	return nil
}

func (f *fakeTeamStore) RecordHostedCheckout(_ context.Context, teamID uuid.UUID, sessionID string, quantity int, startedAt time.Time) error {
	t := f.teams[teamID]
	t.SubscriptionStatus = "pending"
	t.PaidSeats = quantity
	t.CheckoutSessionID = &sessionID
	t.CheckoutStartedAt = &startedAt
	f.teams[teamID] = t
	return nil
}

func (f *fakeTeamStore) BeginCheckout(_ context.Context, teamID uuid.UUID, quantity int, startedAt time.Time) (db.CheckoutReservation, error) {
	t := f.teams[teamID]
	if t.SubscriptionStatus == "active" || t.SubscriptionStatus == "on_hold" {
		return db.CheckoutReservation{}, db.ErrLiveSubscription
	}
	if t.SubscriptionStatus == "pending" && t.CheckoutStartedAt != nil && startedAt.Sub(*t.CheckoutStartedAt) < 24*time.Hour {
		if t.CheckoutAttemptID != nil && t.PaidSeats == quantity {
			return db.CheckoutReservation{AttemptID: *t.CheckoutAttemptID}, nil
		}
		return db.CheckoutReservation{}, db.ErrCheckoutInProgress
	}
	attemptID := uuid.New()
	t.SubscriptionStatus = "pending"
	t.PaidSeats = quantity
	t.DodoSubscriptionID = nil
	t.CheckoutAttemptID = &attemptID
	t.CheckoutStartedAt = &startedAt
	f.teams[teamID] = t
	return db.CheckoutReservation{AttemptID: attemptID}, nil
}

func (f *fakeTeamStore) CompleteCheckoutReservation(_ context.Context, teamID uuid.UUID, attemptID uuid.UUID, sessionID string) error {
	t := f.teams[teamID]
	if t.CheckoutAttemptID == nil || *t.CheckoutAttemptID != attemptID {
		return errors.New("checkout reservation no longer current")
	}
	t.CheckoutSessionID = &sessionID
	f.teams[teamID] = t
	return nil
}

func (f *fakeTeamStore) ReleaseCheckoutReservation(_ context.Context, teamID uuid.UUID, attemptID uuid.UUID) error {
	t := f.teams[teamID]
	if t.CheckoutAttemptID != nil && *t.CheckoutAttemptID == attemptID {
		t.SubscriptionStatus = "none"
		t.PaidSeats = 0
		t.CheckoutAttemptID = nil
		t.CheckoutStartedAt = nil
	}
	f.teams[teamID] = t
	return nil
}

func (f *fakeTeamStore) ReserveSeatCountChange(_ context.Context, teamID uuid.UUID, quantity int, _ time.Time) (db.SeatCountReservation, error) {
	t := f.teams[teamID]
	if (t.SubscriptionStatus != "active" && t.SubscriptionStatus != "on_hold") || t.DodoSubscriptionID == nil || *t.DodoSubscriptionID == "" {
		return db.SeatCountReservation{}, db.ErrLiveSubscription
	}
	if t.PendingPaidSeats != nil {
		if *t.PendingPaidSeats == quantity && t.SeatCountAttemptID != nil {
			return db.SeatCountReservation{AttemptID: *t.SeatCountAttemptID, Attached: len(f.seats[teamID]), Reused: true}, nil
		}
		return db.SeatCountReservation{}, db.ErrSeatCountChangeInProgress
	}
	attached := len(f.seats[teamID])
	if attached > quantity {
		return db.SeatCountReservation{Attached: attached}, db.ErrSeatCapacityReached
	}
	attemptID := uuid.New()
	t.PendingPaidSeats = &quantity
	t.SeatCountAttemptID = &attemptID
	f.teams[teamID] = t
	return db.SeatCountReservation{AttemptID: attemptID, Attached: attached}, nil
}

func (f *fakeTeamStore) ReleaseSeatCountChange(_ context.Context, teamID uuid.UUID, attemptID uuid.UUID) error {
	t := f.teams[teamID]
	if t.SeatCountAttemptID != nil && *t.SeatCountAttemptID == attemptID {
		t.PendingPaidSeats = nil
		t.SeatCountAttemptID = nil
	}
	f.teams[teamID] = t
	return nil
}

func (f *fakeTeamStore) BindCurrentSubscription(_ context.Context, teamID uuid.UUID, subID, customerID, status string, paidSeats int) error {
	t := f.teams[teamID]
	if t.SubscriptionStatus != "pending" && (t.DodoSubscriptionID == nil || *t.DodoSubscriptionID != subID) {
		return db.ErrStaleSubscription
	}
	if isTerminalStatus(t.SubscriptionStatus) && !isTerminalStatus(status) {
		return db.ErrStaleSubscription
	}
	t.SubscriptionStatus = status
	t.PaidSeats = paidSeats
	t.DodoSubscriptionID = &subID
	t.DodoCustomerID = &customerID
	t.CheckoutAttemptID = nil
	t.PendingPaidSeats = nil
	t.SeatCountAttemptID = nil
	f.teams[teamID] = t
	return nil
}

func isTerminalStatus(status string) bool {
	return status == "failed" || status == "cancelled" || status == "expired"
}

func (f *fakeTeamStore) IsWebhookProcessed(context.Context, string) (bool, error) { return false, nil }
func (f *fakeTeamStore) MarkWebhookProcessed(context.Context, string) error       { return nil }
func (f *fakeTeamStore) HasManualVerificationGrant(_ context.Context, mxid string) (bool, error) {
	return f.manual[mxid], nil
}
func (f *fakeTeamStore) HasBillingVerificationGrant(_ context.Context, mxid string) (bool, error) {
	return f.billing[mxid], nil
}
func (f *fakeTeamStore) InsertBillingVerificationGrant(_ context.Context, _ uuid.UUID, mxid string) error {
	f.billing[mxid] = true
	return nil
}
func (f *fakeTeamStore) DeleteBillingVerificationGrant(_ context.Context, mxid string) error {
	delete(f.billing, mxid)
	return nil
}

func TestHandleDeleteSeat_RevokesBeforeRemovingSeat(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, AdminMXID: "@admin:telecrypt.io", SubscriptionStatus: "active", PaidSeats: 1}
	store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}
	store.billing["@seat:telecrypt.io"] = true
	synapse := &fakeSynapse{}
	srv := &Server{store: store, reconciler: NewReconciler(store, synapse)}

	req := httptest.NewRequest(http.MethodDelete, "/api/team/seats/@seat:telecrypt.io", nil)
	req.SetPathValue("mxid", "@seat:telecrypt.io")
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()
	srv.handleDeleteSeat(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if store.billing["@seat:telecrypt.io"] {
		t.Fatal("deleted seat remains locally billing-verified")
	}
	if got, want := synapse.cleared, []string{"@seat:telecrypt.io"}; !equalStrings(got, want) {
		t.Fatalf("Synapse clears = %v, want %v", got, want)
	}
	if got := store.seats[teamID]; len(got) != 0 {
		t.Fatalf("seat row remains after successful revoke: %v", got)
	}
}

func TestHandleSubscriptionRevocation_CancelledAndExpiredRevokeSeats(t *testing.T) {
	for _, status := range []string{"cancelled", "expired"} {
		t.Run(status, func(t *testing.T) {
			store := newFakeTeamStore()
			teamID := uuid.New()
			subID := "sub_123"
			store.teams[teamID] = db.Team{
				ID:                 teamID,
				SubscriptionStatus: "active",
				PaidSeats:          1,
				DodoSubscriptionID: &subID,
			}
			store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}
			store.billing["@seat:telecrypt.io"] = true
			synapse := &fakeSynapse{}
			srv := &Server{
				cfg:        &config.CashierConfig{DodoProductID: "prod_test"},
				store:      store,
				reconciler: NewReconciler(store, synapse),
			}

			var event dodo.UnwrapWebhookEvent
			payload := `{"type":"subscription.` + status + `","data":{"subscription_id":"` + subID + `","product_id":"prod_test","quantity":1}}`
			if err := json.Unmarshal([]byte(payload), &event); err != nil {
				t.Fatalf("decode Dodo %s event: %v", status, err)
			}
			err := srv.processWebhook(context.Background(), &event)
			if err != nil {
				t.Fatalf("revoke: %v", err)
			}
			if got := store.teams[teamID].SubscriptionStatus; got != status {
				t.Fatalf("subscription status = %q, want %q", got, status)
			}
			if store.billing["@seat:telecrypt.io"] {
				t.Fatal("terminal subscription state leaves billing grant")
			}
			if got, want := synapse.cleared, []string{"@seat:telecrypt.io"}; !equalStrings(got, want) {
				t.Fatalf("Synapse clears = %v, want %v", got, want)
			}
		})
	}
}

func TestHandleCheckout_RejectsExistingLiveSubscription(t *testing.T) {
	for _, status := range []string{"pending", "active", "on_hold"} {
		t.Run(status, func(t *testing.T) {
			store := newFakeTeamStore()
			teamID := uuid.New()
			subscriptionID := "sub_current"
			startedAt := time.Now()
			store.teams[teamID] = db.Team{
				ID:                 teamID,
				AdminMXID:          "@admin:telecrypt.io",
				DodoSubscriptionID: &subscriptionID,
				SubscriptionStatus: status,
			}
			if status == "pending" {
				team := store.teams[teamID]
				team.CheckoutStartedAt = &startedAt
				store.teams[teamID] = team
			}
			srv := &Server{store: store}
			req := httptest.NewRequest(http.MethodPost, "/api/team/checkout", strings.NewReader(`{"quantity":2}`))
			req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
			rec := httptest.NewRecorder()

			srv.handleCheckout(rec, req)

			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandleCheckout_CreatesOneIdempotentHostedSession(t *testing.T) {
	var calls int
	var idempotencyKey string
	var firstIdempotencyKey string
	var checkoutBody map[string]any
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		idempotencyKey = r.Header.Get("Idempotency-Key")
		if r.Method != http.MethodPost || r.URL.Path != "/checkouts" {
			t.Errorf("provider request = %s %s, want POST /checkouts", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&checkoutBody); err != nil {
			t.Errorf("decode checkout body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"checkout_url":"https://test.checkout.example/session","session_id":"chk_test"}`))
	}))
	t.Cleanup(provider.Close)

	store := newFakeTeamStore()
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, AdminMXID: "@admin:telecrypt.io", SubscriptionStatus: "none"}
	client := dodo.NewClient(
		option.WithBaseURL(provider.URL),
		option.WithBearerToken("test-key"),
		option.WithMaxRetries(0),
	)
	srv := &Server{
		cfg:   &config.CashierConfig{DodoProductID: "prod_test", PlanPublicURL: "https://plan.test.telecrypt.io/plan"},
		store: store,
		dodo:  client,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/team/checkout", strings.NewReader(`{"quantity":2}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()
	srv.handleCheckout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first checkout status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if calls != 1 || idempotencyKey == "" {
		t.Fatalf("provider calls=%d idempotency=%q, want one call with key", calls, idempotencyKey)
	}
	firstIdempotencyKey = idempotencyKey
	metadata, ok := checkoutBody["metadata"].(map[string]any)
	if !ok || metadata["team_id"] != teamID.String() || metadata["checkout_attempt_id"] != idempotencyKey {
		t.Fatalf("checkout metadata = %#v, want team and matching attempt id", checkoutBody["metadata"])
	}
	team := store.teams[teamID]
	if team.CheckoutSessionID == nil || *team.CheckoutSessionID != "chk_test" || team.PaidSeats != 2 {
		t.Fatalf("checkout reservation not completed: %+v", team)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/team/checkout", strings.NewReader(`{"quantity":2}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec = httptest.NewRecorder()
	srv.handleCheckout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovered checkout status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if calls != 2 || idempotencyKey != firstIdempotencyKey {
		t.Fatalf("recovery calls=%d keys=%q/%q, want two requests with one durable key", calls, firstIdempotencyKey, idempotencyKey)
	}
}

func TestHandleCheckout_AmbiguousFailureRetriesSameDurableAttempt(t *testing.T) {
	var keys []string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if len(keys) == 1 {
			http.Error(w, "response lost after provider accepted request", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"checkout_url":"https://test.checkout.example/recovered","session_id":"chk_recovered"}`))
	}))
	defer provider.Close()

	store := newFakeTeamStore()
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, AdminMXID: "@admin:telecrypt.io", SubscriptionStatus: "none"}
	client := dodo.NewClient(option.WithBaseURL(provider.URL), option.WithBearerToken("test-key"), option.WithMaxRetries(0))
	srv := &Server{
		cfg:   &config.CashierConfig{DodoProductID: "prod_test", PlanPublicURL: "https://plan.test.telecrypt.io/plan"},
		store: store,
		dodo:  client,
	}
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/team/checkout", strings.NewReader(`{"quantity":2}`))
		req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
		rec := httptest.NewRecorder()
		srv.handleCheckout(rec, req)
		return rec
	}

	if rec := request(); rec.Code != http.StatusBadGateway {
		t.Fatalf("ambiguous response status = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if rec := request(); rec.Code != http.StatusOK {
		t.Fatalf("recovery status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("provider idempotency keys = %v, want same non-empty key", keys)
	}
}

func TestHandleChangeSeatCount_UpgradeUsesExistingSubscription(t *testing.T) {
	var requestBody map[string]any
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/subscriptions/sub_current/change-plan" {
			t.Errorf("provider request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Errorf("decode change-plan body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(provider.Close)

	store := newFakeTeamStore()
	teamID := uuid.New()
	subID := "sub_current"
	store.teams[teamID] = db.Team{
		ID:                 teamID,
		AdminMXID:          "@admin:telecrypt.io",
		DodoSubscriptionID: &subID,
		SubscriptionStatus: "active",
		PaidSeats:          2,
	}
	client := dodo.NewClient(
		option.WithBaseURL(provider.URL),
		option.WithBearerToken("test-key"),
		option.WithMaxRetries(0),
	)
	srv := &Server{
		cfg:   &config.CashierConfig{DodoProductID: "prod_test"},
		store: store,
		dodo:  client,
	}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seat-count", strings.NewReader(`{"quantity":3}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()

	srv.handleChangeSeatCount(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("upgrade status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if requestBody["product_id"] != "prod_test" || requestBody["quantity"] != float64(3) {
		t.Fatalf("change-plan body = %#v", requestBody)
	}
	if requestBody["effective_at"] != "immediately" || requestBody["on_payment_failure"] != "prevent_change" {
		t.Fatalf("unsafe change-plan controls: %#v", requestBody)
	}
}

func TestHandleChangeSeatCount_DowngradeReservesCapacityBeforeProviderCall(t *testing.T) {
	providerEntered := make(chan struct{})
	releaseProvider := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(providerEntered)
		<-releaseProvider
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer provider.Close()

	store := newFakeTeamStore()
	teamID := uuid.New()
	subID := "sub_current"
	store.teams[teamID] = db.Team{
		ID: teamID, AdminMXID: "@admin:telecrypt.io", DodoSubscriptionID: &subID,
		SubscriptionStatus: "active", PaidSeats: 3,
	}
	store.seats[teamID] = []db.Seat{{MXID: "@first:telecrypt.io", TeamID: teamID}}
	client := dodo.NewClient(option.WithBaseURL(provider.URL), option.WithBearerToken("test"), option.WithMaxRetries(0))
	srv := &Server{cfg: &config.CashierConfig{DodoProductID: "prod_test"}, store: store, dodo: client}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seat-count", strings.NewReader(`{"quantity":1}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.handleChangeSeatCount(rec, req)
		close(done)
	}()
	<-providerEntered

	if err := store.AttachSeat(context.Background(), teamID, "@racer:telecrypt.io"); !errors.Is(err, db.ErrSeatCapacityReached) {
		t.Fatalf("concurrent AttachSeat error = %v, want ErrSeatCapacityReached", err)
	}
	close(releaseProvider)
	<-done
	if rec.Code != http.StatusOK {
		t.Fatalf("downgrade status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleChangeSeatCount_AmbiguousProviderFailureRetainsCapacityReservation(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider failed", http.StatusInternalServerError)
	}))
	defer provider.Close()

	store := newFakeTeamStore()
	teamID := uuid.New()
	subID := "sub_current"
	store.teams[teamID] = db.Team{
		ID: teamID, AdminMXID: "@admin:telecrypt.io", DodoSubscriptionID: &subID,
		SubscriptionStatus: "active", PaidSeats: 3,
	}
	client := dodo.NewClient(option.WithBaseURL(provider.URL), option.WithBearerToken("test"), option.WithMaxRetries(0))
	srv := &Server{cfg: &config.CashierConfig{DodoProductID: "prod_test"}, store: store, dodo: client}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seat-count", strings.NewReader(`{"quantity":1}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()

	srv.handleChangeSeatCount(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if got := store.teams[teamID].PendingPaidSeats; got == nil || *got != 1 {
		t.Fatalf("ambiguous provider failure pending cap = %v, want 1 retained", got)
	}
}

func TestHandleChangeSeatCount_KnownRejectionReleasesCapacityReservation(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"invalid quantity"}`, http.StatusUnprocessableEntity)
	}))
	defer provider.Close()

	store := newFakeTeamStore()
	teamID := uuid.New()
	subID := "sub_current"
	store.teams[teamID] = db.Team{
		ID: teamID, AdminMXID: "@admin:telecrypt.io", DodoSubscriptionID: &subID,
		SubscriptionStatus: "active", PaidSeats: 3,
	}
	client := dodo.NewClient(option.WithBaseURL(provider.URL), option.WithBearerToken("test"), option.WithMaxRetries(0))
	srv := &Server{cfg: &config.CashierConfig{DodoProductID: "prod_test"}, store: store, dodo: client}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seat-count", strings.NewReader(`{"quantity":1}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()

	srv.handleChangeSeatCount(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if got := store.teams[teamID].PendingPaidSeats; got != nil {
		t.Fatalf("known provider rejection left pending cap %v", *got)
	}
}

func TestWebhookDedupKeyIncludesExplicitEnvironment(t *testing.T) {
	srv := &Server{cfg: &config.CashierConfig{TelecryptEnv: "test"}}
	if got, want := srv.webhookDedupKey("msg_123"), "test:msg_123"; got != want {
		t.Fatalf("webhookDedupKey = %q, want %q", got, want)
	}
}

func TestHandleReconcileSeatCount_RepairsMissedWebhookFromProviderSnapshot(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/subscriptions/sub_current" {
			t.Errorf("provider request = %s %s, want GET /subscriptions/sub_current", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"subscription_id":"sub_current",
			"product_id":"prod_test",
			"quantity":3,
			"status":"active",
			"customer":{"customer_id":"cus_test"},
			"metadata":{}
		}`))
	}))
	defer provider.Close()

	store := newFakeTeamStore()
	teamID := uuid.New()
	subID := "sub_current"
	pending := 3
	attemptID := uuid.New()
	store.teams[teamID] = db.Team{
		ID: teamID, AdminMXID: "@admin:telecrypt.io", DodoSubscriptionID: &subID,
		SubscriptionStatus: "active", PaidSeats: 2, PendingPaidSeats: &pending,
		SeatCountAttemptID: &attemptID,
	}
	client := dodo.NewClient(option.WithBaseURL(provider.URL), option.WithBearerToken("test"), option.WithMaxRetries(0))
	srv := &Server{
		cfg:        &config.CashierConfig{DodoProductID: "prod_test"},
		store:      store,
		reconciler: NewReconciler(store, &fakeSynapse{}),
		dodo:       client,
	}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seat-count/reconcile", nil)
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()

	srv.handleReconcileSeatCount(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	team := store.teams[teamID]
	if team.PaidSeats != 3 || team.PendingPaidSeats != nil || team.SeatCountAttemptID != nil {
		t.Fatalf("reconciled team = %+v, want paid=3 and no pending reservation", team)
	}
}

func TestHandleChangeSeatCount_BlocksDowngradeBelowAttachedSeats(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	subID := "sub_current"
	store.teams[teamID] = db.Team{
		ID:                 teamID,
		AdminMXID:          "@admin:telecrypt.io",
		DodoSubscriptionID: &subID,
		SubscriptionStatus: "active",
		PaidSeats:          3,
	}
	store.seats[teamID] = []db.Seat{
		{MXID: "@bot-a:telecrypt.io", TeamID: teamID},
		{MXID: "@bot-b:telecrypt.io", TeamID: teamID},
	}
	srv := &Server{cfg: &config.CashierConfig{DodoProductID: "prod_test"}, store: store}
	req := httptest.NewRequest(http.MethodPost, "/api/team/seat-count", strings.NewReader(`{"quantity":1}`))
	req = req.WithContext(withMXID(req.Context(), "@admin:telecrypt.io"))
	rec := httptest.NewRecorder()

	srv.handleChangeSeatCount(rec, req)

	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "remove 1 seat") {
		t.Fatalf("downgrade response = %d %q, want guarded 409", rec.Code, rec.Body.String())
	}
}

func TestProcessWebhook_IgnoresOldSubscriptionAfterNewerSubscriptionBound(t *testing.T) {
	for _, eventType := range []string{"active", "cancelled"} {
		t.Run(eventType, func(t *testing.T) {
			store := newFakeTeamStore()
			teamID := uuid.New()
			currentSubscriptionID := "sub_current"
			store.teams[teamID] = db.Team{
				ID:                 teamID,
				SubscriptionStatus: "active",
				PaidSeats:          2,
				DodoSubscriptionID: &currentSubscriptionID,
			}
			store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}
			store.billing["@seat:telecrypt.io"] = true
			synapse := &fakeSynapse{}
			srv := &Server{
				cfg:        &config.CashierConfig{DodoProductID: "prod_test"},
				store:      store,
				reconciler: NewReconciler(store, synapse),
			}

			var event dodo.UnwrapWebhookEvent
			payload := `{"type":"subscription.` + eventType + `","data":{"subscription_id":"sub_old","product_id":"prod_test","quantity":1,"metadata":{"team_id":"` + teamID.String() + `"}}}`
			if err := json.Unmarshal([]byte(payload), &event); err != nil {
				t.Fatalf("decode Dodo event: %v", err)
			}
			if err := srv.processWebhook(context.Background(), &event); err != nil {
				t.Fatalf("process old event: %v", err)
			}

			team := store.teams[teamID]
			if team.SubscriptionStatus != "active" || team.DodoSubscriptionID == nil || *team.DodoSubscriptionID != currentSubscriptionID {
				t.Fatalf("old event overwrote current subscription: %+v", team)
			}
			if !store.billing["@seat:telecrypt.io"] || len(synapse.cleared) != 0 {
				t.Fatalf("old event revoked current entitlement: billing=%v clears=%v", store.billing, synapse.cleared)
			}
		})
	}
}

func TestProcessWebhook_BindsReplacementSubscriptionAfterTerminalState(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	oldID := "sub_old"
	store.teams[teamID] = db.Team{
		ID:                 teamID,
		SubscriptionStatus: "cancelled",
		PaidSeats:          1,
		DodoSubscriptionID: &oldID,
	}
	if _, err := store.BeginCheckout(context.Background(), teamID, 2, time.Now()); err != nil {
		t.Fatalf("begin replacement checkout: %v", err)
	}
	attemptID := store.teams[teamID].CheckoutAttemptID.String()
	srv := &Server{
		cfg:        &config.CashierConfig{DodoProductID: "prod_test"},
		store:      store,
		reconciler: NewReconciler(store, &fakeSynapse{}),
	}

	var active dodo.UnwrapWebhookEvent
	payload := `{"type":"subscription.active","data":{"subscription_id":"sub_new","product_id":"prod_test","quantity":2,"customer":{"customer_id":"cus_new"},"metadata":{"team_id":"` + teamID.String() + `","checkout_attempt_id":"` + attemptID + `"}}}`
	if err := json.Unmarshal([]byte(payload), &active); err != nil {
		t.Fatalf("decode active event: %v", err)
	}
	if err := srv.processWebhook(context.Background(), &active); err != nil {
		t.Fatalf("process replacement active event: %v", err)
	}
	team := store.teams[teamID]
	if team.DodoSubscriptionID == nil || *team.DodoSubscriptionID != "sub_new" || team.SubscriptionStatus != "active" || team.PaidSeats != 2 {
		t.Fatalf("replacement did not bind correctly: %+v", team)
	}

	var lateOld dodo.UnwrapWebhookEvent
	payload = `{"type":"subscription.cancelled","data":{"subscription_id":"sub_old","product_id":"prod_test","quantity":1,"metadata":{"team_id":"` + teamID.String() + `"}}}`
	if err := json.Unmarshal([]byte(payload), &lateOld); err != nil {
		t.Fatalf("decode delayed event: %v", err)
	}
	if err := srv.processWebhook(context.Background(), &lateOld); err != nil {
		t.Fatalf("process delayed old event: %v", err)
	}
	if got := store.teams[teamID].DodoSubscriptionID; got == nil || *got != "sub_new" {
		t.Fatalf("delayed old event overwrote replacement: %+v", store.teams[teamID])
	}
}

func TestProcessWebhook_RejectsWrongEnvironmentProduct(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	subID := "sub_current"
	store.teams[teamID] = db.Team{
		ID:                 teamID,
		SubscriptionStatus: "active",
		PaidSeats:          2,
		DodoSubscriptionID: &subID,
	}
	srv := &Server{
		cfg:        &config.CashierConfig{DodoProductID: "prod_expected"},
		store:      store,
		reconciler: NewReconciler(store, &fakeSynapse{}),
	}

	var event dodo.UnwrapWebhookEvent
	payload := `{"type":"subscription.updated","data":{"subscription_id":"sub_current","product_id":"prod_other_environment","quantity":9,"status":"active"}}`
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatalf("decode wrong-product event: %v", err)
	}
	err := srv.processWebhook(context.Background(), &event)
	if !errors.Is(err, errUnexpectedDodoProduct) {
		t.Fatalf("processWebhook error = %v, want errUnexpectedDodoProduct", err)
	}
	team := store.teams[teamID]
	if team.PaidSeats != 2 || team.SubscriptionStatus != "active" {
		t.Fatalf("wrong-product event mutated team: %+v", team)
	}
}

func TestProcessWebhook_IgnoresLateAbandonedCheckoutAttempt(t *testing.T) {
	store := newFakeTeamStore()
	teamID := uuid.New()
	store.teams = map[uuid.UUID]db.Team{
		teamID: {ID: teamID, AdminMXID: "@admin:telecrypt.io", SubscriptionStatus: "none"},
	}
	current, err := store.BeginCheckout(context.Background(), teamID, 2, time.Now())
	if err != nil {
		t.Fatalf("begin current checkout: %v", err)
	}
	abandonedAttemptID := uuid.New()
	srv := &Server{
		cfg:        &config.CashierConfig{DodoProductID: "prod_test"},
		store:      store,
		reconciler: NewReconciler(store, &fakeSynapse{}),
	}

	var event dodo.UnwrapWebhookEvent
	payload := `{"type":"subscription.active","data":{"subscription_id":"sub_late","product_id":"prod_test","quantity":9,"customer":{"customer_id":"cus_late"},"metadata":{"team_id":"` +
		teamID.String() + `","checkout_attempt_id":"` + abandonedAttemptID.String() + `"}}}`
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatalf("decode late checkout event: %v", err)
	}
	if err := srv.processWebhook(context.Background(), &event); err != nil {
		t.Fatalf("stale webhook should be acknowledged: %v", err)
	}
	team := store.teams[teamID]
	if team.CheckoutAttemptID == nil || *team.CheckoutAttemptID != current.AttemptID ||
		team.SubscriptionStatus != "pending" || team.PaidSeats != 2 {
		t.Fatalf("late checkout event replaced current attempt: %+v", team)
	}
}
