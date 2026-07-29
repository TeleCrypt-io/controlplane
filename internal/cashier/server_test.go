package cashier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dodo "github.com/dodopayments/dodopayments-go"
	"github.com/google/uuid"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
)

func TestHandlePlan_Unauthenticated(t *testing.T) {
	cfg := &config.CashierConfig{PlanPublicURL: "https://telecrypt.io/plan", ServerName: "telecrypt.io"}
	srv := NewServer(cfg, nil, nil, nil, NewSession("test-key"), nil)

	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, "Log in with your TeleCrypt account") {
		t.Fatalf("expected login prompt, got: %s", body)
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

func (f *fakeTeamStore) InsertSeat(_ context.Context, teamID uuid.UUID, mxid string) error {
	f.seats[teamID] = append(f.seats[teamID], db.Seat{MXID: mxid, TeamID: teamID})
	return nil
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
			srv := &Server{store: store, reconciler: NewReconciler(store, synapse)}

			var event dodo.UnwrapWebhookEvent
			payload := `{"type":"subscription.` + status + `","data":{"subscription_id":"` + subID + `","quantity":1}}`
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
			srv := &Server{store: store, reconciler: NewReconciler(store, synapse)}

			var event dodo.UnwrapWebhookEvent
			payload := `{"type":"subscription.` + eventType + `","data":{"subscription_id":"sub_old","quantity":1,"metadata":{"team_id":"` + teamID.String() + `"}}}`
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
