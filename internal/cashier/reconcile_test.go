package cashier

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/TeleCrypt-io/controlplane/internal/db"
)

type fakeEntitlementStore struct {
	teams     map[uuid.UUID]db.Team
	seats     map[uuid.UUID][]db.Seat
	manual    map[string]bool
	billing   map[string]bool
	insertErr error
	deleteErr error
}

func newFakeEntitlementStore() *fakeEntitlementStore {
	return &fakeEntitlementStore{
		teams:   map[uuid.UUID]db.Team{},
		seats:   map[uuid.UUID][]db.Seat{},
		manual:  map[string]bool{},
		billing: map[string]bool{},
	}
}

func (f *fakeEntitlementStore) GetTeamByID(_ context.Context, teamID uuid.UUID) (db.Team, error) {
	t, ok := f.teams[teamID]
	if !ok {
		return db.Team{}, errTeamNotFound
	}
	return t, nil
}

func (f *fakeEntitlementStore) ListSeatsForTeam(_ context.Context, teamID uuid.UUID) ([]db.Seat, error) {
	return append([]db.Seat(nil), f.seats[teamID]...), nil
}

func (f *fakeEntitlementStore) HasManualVerificationGrant(_ context.Context, mxid string) (bool, error) {
	return f.manual[mxid], nil
}

func (f *fakeEntitlementStore) IsSeatMXID(_ context.Context, mxid string) (bool, error) {
	for _, seats := range f.seats {
		for _, s := range seats {
			if s.MXID == mxid {
				return true, nil
			}
		}
	}
	return false, nil
}

func (f *fakeEntitlementStore) HasBillingVerificationGrant(_ context.Context, mxid string) (bool, error) {
	return f.billing[mxid], nil
}

func (f *fakeEntitlementStore) InsertBillingVerificationGrant(_ context.Context, _ uuid.UUID, mxid string) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.billing[mxid] = true
	return nil
}

func (f *fakeEntitlementStore) DeleteBillingVerificationGrant(_ context.Context, mxid string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.billing, mxid)
	return nil
}

type fakeSynapse struct {
	verified []string
	cleared  []string
	setErr   error
	clearErr error
}

func (f *fakeSynapse) SetUserTypeVerified(_ context.Context, mxid string) error {
	f.verified = append(f.verified, mxid)
	return f.setErr
}

func (f *fakeSynapse) ClearUserType(_ context.Context, mxid string) error {
	f.cleared = append(f.cleared, mxid)
	return f.clearErr
}

var errTeamNotFound = errUnauthorized

func TestReconcileTeamEntitlement_ActiveUnlocksOldestSeats(t *testing.T) {
	store := newFakeEntitlementStore()
	synapse := &fakeSynapse{}
	r := NewReconciler(store, synapse)

	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, SubscriptionStatus: "active", PaidSeats: 2}
	store.seats[teamID] = []db.Seat{
		{MXID: "@a:telecrypt.io", TeamID: teamID},
		{MXID: "@b:telecrypt.io", TeamID: teamID},
		{MXID: "@c:telecrypt.io", TeamID: teamID},
	}

	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got, want := synapse.verified, []string{"@a:telecrypt.io", "@b:telecrypt.io"}; !equalStrings(got, want) {
		t.Fatalf("verified = %v, want %v", got, want)
	}
	if synapse.cleared != nil {
		t.Fatalf("unexpected clears: %v", synapse.cleared)
	}
}

func TestReconcileTeamEntitlement_SkipsManualGrantOutsideSeats(t *testing.T) {
	store := newFakeEntitlementStore()
	synapse := &fakeSynapse{}
	r := NewReconciler(store, synapse)

	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, SubscriptionStatus: "none", PaidSeats: 0}
	store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}
	store.manual["@manual:telecrypt.io"] = true
	store.billing["@seat:telecrypt.io"] = true

	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if store.manual["@manual:telecrypt.io"] != true {
		t.Fatal("manual grant outside seats must remain verified")
	}
	if store.billing["@seat:telecrypt.io"] {
		t.Fatal("seat should be unverified when subscription inactive")
	}
	if got, want := synapse.cleared, []string{"@seat:telecrypt.io"}; !equalStrings(got, want) {
		t.Fatalf("cleared = %v, want %v", got, want)
	}
}

func TestReconcileTeamEntitlement_RetriesAfterSynapseVerifyFailure(t *testing.T) {
	store := newFakeEntitlementStore()
	synapse := &fakeSynapse{setErr: errors.New("synapse unavailable")}
	r := NewReconciler(store, synapse)
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, SubscriptionStatus: "active", PaidSeats: 1}
	store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}

	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err == nil {
		t.Fatal("expected Synapse error")
	}
	if store.billing["@seat:telecrypt.io"] {
		t.Fatal("local billing grant must not advance before Synapse succeeds")
	}

	synapse.setErr = nil
	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if !store.billing["@seat:telecrypt.io"] {
		t.Fatal("retry must record billing state after Synapse succeeds")
	}
	if got, want := synapse.verified, []string{"@seat:telecrypt.io", "@seat:telecrypt.io"}; !equalStrings(got, want) {
		t.Fatalf("verify attempts = %v, want %v", got, want)
	}
}

func TestReconcileTeamEntitlement_RetriesAfterSynapseClearFailure(t *testing.T) {
	store := newFakeEntitlementStore()
	synapse := &fakeSynapse{clearErr: errors.New("synapse unavailable")}
	r := NewReconciler(store, synapse)
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, SubscriptionStatus: "cancelled", PaidSeats: 1}
	store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}
	store.billing["@seat:telecrypt.io"] = true

	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err == nil {
		t.Fatal("expected Synapse error")
	}
	if !store.billing["@seat:telecrypt.io"] {
		t.Fatal("local billing grant must remain until Synapse clear succeeds")
	}

	synapse.clearErr = nil
	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if store.billing["@seat:telecrypt.io"] {
		t.Fatal("retry must remove local billing grant after Synapse succeeds")
	}
	if got, want := synapse.cleared, []string{"@seat:telecrypt.io", "@seat:telecrypt.io"}; !equalStrings(got, want) {
		t.Fatalf("clear attempts = %v, want %v", got, want)
	}
}

func TestReconcileTeamEntitlement_RetriesAfterBillingGrantStoreFailure(t *testing.T) {
	store := newFakeEntitlementStore()
	store.insertErr = errors.New("postgres unavailable")
	synapse := &fakeSynapse{}
	r := NewReconciler(store, synapse)
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, SubscriptionStatus: "active", PaidSeats: 1}
	store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}

	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err == nil {
		t.Fatal("expected local billing-grant write error")
	}
	if store.billing["@seat:telecrypt.io"] {
		t.Fatal("failed local write recorded a billing grant")
	}

	store.insertErr = nil
	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if got, want := synapse.verified, []string{"@seat:telecrypt.io", "@seat:telecrypt.io"}; !equalStrings(got, want) {
		t.Fatalf("remote verification attempts = %v, want %v", got, want)
	}
}

func TestReconcileTeamEntitlement_RetriesAfterBillingGrantDeleteFailure(t *testing.T) {
	store := newFakeEntitlementStore()
	store.deleteErr = errors.New("postgres unavailable")
	synapse := &fakeSynapse{}
	r := NewReconciler(store, synapse)
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, SubscriptionStatus: "failed"}
	store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}
	store.billing["@seat:telecrypt.io"] = true

	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err == nil {
		t.Fatal("expected local billing-grant delete error")
	}
	if !store.billing["@seat:telecrypt.io"] {
		t.Fatal("failed local deletion removed a billing grant")
	}

	store.deleteErr = nil
	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if got, want := synapse.cleared, []string{"@seat:telecrypt.io", "@seat:telecrypt.io"}; !equalStrings(got, want) {
		t.Fatalf("remote clear attempts = %v, want %v", got, want)
	}
}

func TestReconcileTeamEntitlement_RemovingBillingKeepsManualGrant(t *testing.T) {
	store := newFakeEntitlementStore()
	synapse := &fakeSynapse{}
	r := NewReconciler(store, synapse)
	teamID := uuid.New()
	store.teams[teamID] = db.Team{ID: teamID, SubscriptionStatus: "cancelled"}
	store.seats[teamID] = []db.Seat{{MXID: "@seat:telecrypt.io", TeamID: teamID}}
	store.manual["@seat:telecrypt.io"] = true
	store.billing["@seat:telecrypt.io"] = true

	if err := r.ReconcileTeamEntitlement(context.Background(), teamID); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !store.manual["@seat:telecrypt.io"] {
		t.Fatal("manual grant was removed by billing revocation")
	}
	if store.billing["@seat:telecrypt.io"] {
		t.Fatal("billing grant remains after inactive subscription")
	}
	if len(synapse.cleared) != 0 {
		t.Fatalf("manual grant must prevent Synapse clear, got %v", synapse.cleared)
	}
}

func TestRevokeSeat_RemovesOnlyBillingGrantWhenManualGrantRemains(t *testing.T) {
	store := newFakeEntitlementStore()
	synapse := &fakeSynapse{}
	r := NewReconciler(store, synapse)
	store.manual["@seat:telecrypt.io"] = true
	store.billing["@seat:telecrypt.io"] = true

	if err := r.RevokeSeat(context.Background(), "@seat:telecrypt.io"); err != nil {
		t.Fatalf("revoke seat: %v", err)
	}
	if !store.manual["@seat:telecrypt.io"] || store.billing["@seat:telecrypt.io"] {
		t.Fatalf("grants after revoke: manual=%v billing=%v", store.manual, store.billing)
	}
	if len(synapse.cleared) != 0 {
		t.Fatalf("manual grant must prevent Synapse clear, got %v", synapse.cleared)
	}
}

func TestRevokeSeat_ManualGrantDeleteFailureNeverClearsSynapse(t *testing.T) {
	store := newFakeEntitlementStore()
	store.deleteErr = errors.New("postgres unavailable")
	synapse := &fakeSynapse{}
	r := NewReconciler(store, synapse)
	store.manual["@seat:telecrypt.io"] = true
	store.billing["@seat:telecrypt.io"] = true

	if err := r.RevokeSeat(context.Background(), "@seat:telecrypt.io"); err == nil {
		t.Fatal("expected local billing-grant delete error")
	}
	if len(synapse.cleared) != 0 {
		t.Fatalf("manual grant must prevent Synapse clear on failed deletion, got %v", synapse.cleared)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
