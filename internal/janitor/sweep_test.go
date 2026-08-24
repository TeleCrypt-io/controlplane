package janitor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

const testServerName = "stage.telecrypt.io"

func testID(n byte) string { return "01J0000000000000000000000" + string('0'+n) }

type fakeMAS struct {
	users                                     []masadmin.User
	emails                                    []masadmin.UserEmail
	listUsersCalls, listEmailCalls, lockCalls int
}

func (m *fakeMAS) ListUsers(context.Context) ([]masadmin.User, error) {
	m.listUsersCalls++
	return append([]masadmin.User(nil), m.users...), nil
}
func (m *fakeMAS) ListUserEmails(context.Context) ([]masadmin.UserEmail, error) {
	m.listEmailCalls++
	return append([]masadmin.UserEmail(nil), m.emails...), nil
}
func (m *fakeMAS) GetUser(_ context.Context, id string) (masadmin.User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return masadmin.User{}, errors.New("missing")
}
func (m *fakeMAS) HasUserEmail(_ context.Context, id string) (bool, error) {
	for _, e := range m.emails {
		if e.UserID == id {
			return true, nil
		}
	}
	return false, nil
}
func (m *fakeMAS) LockUser(_ context.Context, id string) error {
	m.lockCalls++
	for i := range m.users {
		if m.users[i].ID == id {
			now := time.Now()
			m.users[i].LockedAt = &now
			return nil
		}
	}
	return errors.New("missing")
}

type fakeStore struct {
	exclusions                                    map[string]struct{}
	events                                        []db.RunEvent
	cursor                                        db.DigestCursor
	found                                         bool
	identityErr, viewErr, startedErr, finishedErr error
}

func (s *fakeStore) VerifyDeploymentIdentity(context.Context, string, string) error {
	return s.identityErr
}
func (s *fakeStore) LockExclusions(context.Context) (map[string]struct{}, error) {
	if s.viewErr != nil {
		return nil, s.viewErr
	}
	return s.exclusions, nil
}
func (s *fakeStore) JanitorDigestCursor(context.Context) (db.DigestCursor, bool, error) {
	return s.cursor, s.found, nil
}
func (s *fakeStore) SetJanitorDigestCursor(_ context.Context, c db.DigestCursor) error {
	s.cursor, s.found = c, true
	return nil
}
func (s *fakeStore) InsertRunEvent(_ context.Context, event db.RunEvent) error {
	if event.EventKind == "started" && s.startedErr != nil {
		return s.startedErr
	}
	if event.EventKind == "finished" && s.finishedErr != nil {
		return s.finishedErr
	}
	s.events = append(s.events, event)
	return nil
}

type fakeMailer struct{ calls int }

func (m *fakeMailer) Send(context.Context, string, string, string) error { m.calls++; return nil }

func staleUser(id, username string) masadmin.User {
	return masadmin.User{ID: id, Username: username, CreatedAt: time.Now().Add(-72 * time.Hour)}
}

func testConfig() Config {
	return Config{ServerName: testServerName, BillingEnvironment: "test", DryRun: true}
}

func TestSweepUsesOnlyCashierExclusionViewAndWritesExactDryRunAudit(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(1), "paid"), staleUser(testID(2), "free")}}
	store := &fakeStore{exclusions: map[string]struct{}{"@paid:" + testServerName: {}}}
	sweeper := NewSweeper(mas, store, &fakeMailer{}, testConfig())
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if mas.lockCalls != 0 {
		t.Fatalf("dry-run called MAS lock %d times", mas.lockCalls)
	}
	if len(store.events) != 2 {
		t.Fatalf("audit events = %d, want started and finished", len(store.events))
	}
	finished := store.events[1]
	if finished.EventKind != "finished" || finished.Status != "succeeded" || finished.Outcome != "dry_run" || finished.Reason != "would_disable" || finished.LockedOrWouldLock != 1 {
		t.Fatalf("finished event = %#v", finished)
	}
	if finished.RunID != store.events[0].RunID || finished.EventID == store.events[0].EventID {
		t.Fatalf("audit IDs are not distinct per event/run")
	}
	for _, label := range finished.Labels {
		if label == "@paid:"+testServerName || label == "paid" {
			t.Fatalf("audit label contains an identifier: %q", label)
		}
	}
}

func TestSweepLiveLocksEligibleUserWithoutUnlockOrCompensation(t *testing.T) {
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(3), "free")}}
	store := &fakeStore{exclusions: map[string]struct{}{}}
	cfg := Config{ServerName: "telecrypt.io", BillingEnvironment: "live", DryRun: false, OwnerEmail: "owner@example.test"}
	sweeper := NewSweeper(mas, store, &fakeMailer{}, cfg)
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if mas.lockCalls != 1 {
		t.Fatalf("MAS lock calls = %d, want one", mas.lockCalls)
	}
	if got := store.events[1].Reason; got != "disabled" {
		t.Fatalf("finished reason = %q, want disabled", got)
	}
}

func TestSweepEntitlementViewFailurePreventsMASEnumeration(t *testing.T) {
	mas := &fakeMAS{}
	store := &fakeStore{viewErr: errors.New("private view unavailable")}
	if err := NewSweeper(mas, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted entitlement-view failure")
	}
	if mas.listUsersCalls != 0 || mas.listEmailCalls != 0 {
		t.Fatal("MAS enumeration occurred after entitlement-view failure")
	}
	if len(store.events) != 2 || store.events[1].Reason != "entitlement_view" {
		t.Fatalf("audit events = %#v", store.events)
	}
}

func TestSweepRequiredAuditWriteFailureIsNonSuccess(t *testing.T) {
	store := &fakeStore{startedErr: errors.New("audit unavailable")}
	if err := NewSweeper(&fakeMAS{}, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted started-audit failure")
	}
	if len(store.events) != 0 {
		t.Fatal("recorded audit event despite failed started write")
	}

	store = &fakeStore{}
	store.finishedErr = errors.New("audit unavailable")
	mas := &fakeMAS{users: []masadmin.User{staleUser(testID(4), "free")}}
	if err := NewSweeper(mas, store, &fakeMailer{}, testConfig()).Sweep(context.Background()); err == nil {
		t.Fatal("Sweep accepted finished-audit failure")
	}
	if len(store.events) != 1 || store.events[0].EventKind != "started" {
		t.Fatalf("events after finished failure = %#v", store.events)
	}
}

func TestSweepRejectsHostnameOnlyOrDryRunProfileMismatch(t *testing.T) {
	for _, cfg := range []Config{{ServerName: "preview.telecrypt.io", BillingEnvironment: "test", DryRun: true}, {ServerName: testServerName, BillingEnvironment: "live", DryRun: true}} {
		store := &fakeStore{}
		if err := NewSweeper(&fakeMAS{}, store, &fakeMailer{}, cfg).Sweep(context.Background()); err == nil {
			t.Fatal("Sweep accepted invalid billing profile")
		}
		if len(store.events) != 0 {
			t.Fatal("invalid profile emitted an audit event")
		}
	}
}
