package janitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

// --- httptest fake MAS admin server ---------------------------------------------------------
//
// Reproduces just enough of MAS 1.16.0's admin API (token, paginated users, paginated
// user-emails, lock) for Sweeper to run against a real *masadmin.Client, per the task's test
// requirements. See internal/masadmin/client_test.go for the more thorough per-endpoint tests of
// the client itself; this fake is deliberately simpler (no real cursor-boundary edge cases) since
// the sweep tests below use small fixed user sets.

type fakeUser struct {
	id            string
	username      string
	createdAt     time.Time
	lockedAt      *time.Time
	deactivatedAt *time.Time
}

type fakeMAS struct {
	clientID, clientSecret string

	mu                   sync.Mutex
	users                []*fakeUser
	emails               map[string]string // user id -> email
	lockCalls            []string          // ids passed to POST .../lock, in call order
	unlockCalls          []string          // ids passed to POST .../unlock, in call order
	afterLock            func()
	lockResponseFailures int
	unlockFailures       int
}

func newFakeMAS(clientID, clientSecret string) *fakeMAS {
	return &fakeMAS{clientID: clientID, clientSecret: clientSecret, emails: map[string]string{}}
}

func (f *fakeMAS) addUser(id, username string, createdAt time.Time) *fakeUser {
	u := &fakeUser{id: id, username: username, createdAt: createdAt}
	f.users = append(f.users, u)
	return u
}

func (f *fakeMAS) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", f.handleToken)
	mux.HandleFunc("GET /api/admin/v1/users", f.handleListUsers)
	mux.HandleFunc("GET /api/admin/v1/user-emails", f.handleListEmails)
	mux.HandleFunc("POST /api/admin/v1/users/{id}/lock", f.handleLock)
	mux.HandleFunc("POST /api/admin/v1/users/{id}/unlock", f.handleUnlock)
	return httptest.NewServer(mux)
}

func (f *fakeMAS) handleToken(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != f.clientID || pass != f.clientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"title":"invalid_client"}]}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":300}`)
}

func (f *fakeMAS) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

type userAttrs struct {
	Username      string     `json:"username"`
	CreatedAt     time.Time  `json:"created_at"`
	LockedAt      *time.Time `json:"locked_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
	Admin         bool       `json:"admin"`
	LegacyGuest   bool       `json:"legacy_guest"`
}

type emailAttrs struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
}

func (f *fakeMAS) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	sorted := append([]*fakeUser(nil), f.users...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].id < sorted[j].id })

	type resource struct {
		Type       string    `json:"type"`
		ID         string    `json:"id"`
		Attributes userAttrs `json:"attributes"`
	}
	data := make([]resource, len(sorted))
	for i, u := range sorted {
		data[i] = resource{Type: "user", ID: u.id, Attributes: userAttrs{
			Username: u.username, CreatedAt: u.createdAt, LockedAt: u.lockedAt,
			DeactivatedAt: u.deactivatedAt,
		}}
	}
	writeOnePage(w, data)
}

func (f *fakeMAS) handleListEmails(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	type resource struct {
		Type       string     `json:"type"`
		ID         string     `json:"id"`
		Attributes emailAttrs `json:"attributes"`
	}
	var data []resource
	i := 0
	for userID, email := range f.emails {
		data = append(data, resource{Type: "user-email", ID: fmt.Sprintf("email-%d", i), Attributes: emailAttrs{
			CreatedAt: time.Now().UTC(), UserID: userID, Email: email,
		}})
		i++
	}
	writeOnePage(w, data)
}

// writeOnePage writes a single-page (no "links.next") paginated envelope -- the sweep tests here
// use small fixed sets well under the client's page size, so no cursor-chaining behavior is
// exercised (that's covered by internal/masadmin's own pagination test).
func writeOnePage[T any](w http.ResponseWriter, data T) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"data": data, "links": map[string]any{}}) //nolint:errcheck
}

func (f *fakeMAS) handleLock(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	id := r.PathValue("id")

	f.mu.Lock()
	f.lockCalls = append(f.lockCalls, id)
	for _, u := range f.users {
		if u.id == id {
			if u.lockedAt == nil {
				now := time.Now().UTC()
				u.lockedAt = &now
			}
			hook := f.afterLock
			failResponse := f.lockResponseFailures > 0
			if failResponse {
				f.lockResponseFailures--
			}
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
			if failResponse {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"errors":[{"title":"injected post-commit lock response failure"}]}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "user",
				"id":   u.id,
				"attributes": map[string]any{
					"username":   u.username,
					"created_at": u.createdAt,
					"locked_at":  u.lockedAt,
				},
			}}) //nolint:errcheck
			return
		}
	}
	f.mu.Unlock()
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{"errors":[{"title":"User ID %s not found"}]}`, id)
}

func (f *fakeMAS) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	id := r.PathValue("id")

	f.mu.Lock()
	defer f.mu.Unlock()
	f.unlockCalls = append(f.unlockCalls, id)
	if f.unlockFailures > 0 {
		f.unlockFailures--
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"errors":[{"title":"injected unlock failure"}]}`)
		return
	}
	for _, u := range f.users {
		if u.id == id {
			u.lockedAt = nil
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "user",
				"id":   u.id,
				"attributes": map[string]any{
					"username":   u.username,
					"created_at": u.createdAt,
					"locked_at":  u.lockedAt,
				},
			}}) //nolint:errcheck
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{"errors":[{"title":"User ID %s not found"}]}`, id)
}

// --- fake store and mailer --------------------------------------------------------------------

type verificationResult struct {
	verified bool
	err      error
}

type fakeStore struct {
	mu           sync.Mutex
	verified     map[string]bool
	verifyQueue  map[string][]verificationResult
	janitorLocks map[string]time.Time
	pendingLocks map[string]time.Time
	highWater    map[string]time.Time
	beginErr     error
	confirmErr   error

	// setErr, when non-nil, is returned by SetLockerHighWaterMark -- used to prove a failed
	// digest send/store update doesn't advance the mark.
	setErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		verified:     map[string]bool{},
		verifyQueue:  map[string][]verificationResult{},
		janitorLocks: map[string]time.Time{},
		pendingLocks: map[string]time.Time{},
		highWater:    map[string]time.Time{},
	}
}

func (s *fakeStore) VerifiedMXIDs(ctx context.Context) (map[string]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.verified))
	for mxid, verified := range s.verified {
		out[mxid] = verified
	}
	return out, nil
}

func (s *fakeStore) IsVerified(ctx context.Context, mxid string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if queue := s.verifyQueue[mxid]; len(queue) > 0 {
		result := queue[0]
		s.verifyQueue[mxid] = queue[1:]
		return result.verified, result.err
	}
	return s.verified[mxid], nil
}

func (s *fakeStore) setVerified(mxid string, verified bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verified[mxid] = verified
}

func (s *fakeStore) queueVerification(mxid string, results ...verificationResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyQueue[mxid] = append(s.verifyQueue[mxid], results...)
}

func (s *fakeStore) JanitorLockState(ctx context.Context) (
	confirmed, pending map[string]time.Time,
	err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	confirmed = make(map[string]time.Time, len(s.janitorLocks))
	pending = make(map[string]time.Time, len(s.pendingLocks))
	for userID, lockedAt := range s.janitorLocks {
		confirmed[userID] = lockedAt
	}
	for userID, beganAt := range s.pendingLocks {
		pending[userID] = beganAt
	}
	return confirmed, pending, nil
}

func (s *fakeStore) BeginJanitorLock(ctx context.Context, userID string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.beginErr != nil {
		return time.Time{}, s.beginErr
	}
	beganAt := time.Now().UTC()
	s.pendingLocks[userID] = beganAt
	return beganAt, nil
}

func (s *fakeStore) ConfirmJanitorLock(ctx context.Context, userID string, lockedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmErr != nil {
		return s.confirmErr
	}
	s.janitorLocks[userID] = lockedAt
	delete(s.pendingLocks, userID)
	return nil
}

func (s *fakeStore) DeleteJanitorLock(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.janitorLocks, userID)
	delete(s.pendingLocks, userID)
	return nil
}

func (s *fakeStore) setJanitorLocked(userID string, lockedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.janitorLocks[userID] = lockedAt
}

func (s *fakeStore) LockerHighWaterMark(ctx context.Context, key string) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.highWater[key]
	return v, ok, nil
}

func (s *fakeStore) SetLockerHighWaterMark(ctx context.Context, key string, value time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
	s.highWater[key] = value
	return nil
}

type fakeMailer struct {
	mu       sync.Mutex
	sends    []string // subjects, in call order
	lastTo   string
	lastBody string
	sendErr  error
}

func (m *fakeMailer) Send(ctx context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sends = append(m.sends, subject)
	m.lastTo = to
	m.lastBody = body
	return nil
}

// --- tests -------------------------------------------------------------------------------------

const serverName = "telecrypt.io"

func newSweeperForTest(t *testing.T, mas *fakeMAS, store *fakeStore, mailer Mailer, cfg Config) (*Sweeper, *httptest.Server) {
	t.Helper()
	srv := mas.server()
	t.Cleanup(srv.Close)
	client := masadmin.NewClient(srv.URL, mas.clientID, mas.clientSecret)
	cfg.ServerName = serverName
	return NewSweeper(client, store, mailer, cfg), srv
}

// TestSweep_LocksOnlyStaleUnclaimedEmaillessAccounts is the core scenario: eight accounts, each
// disqualified from locking for a different reason except one.
func TestSweep_LocksOnlyStaleUnclaimedEmaillessAccounts(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	old := time.Now().Add(-72 * time.Hour)
	young := time.Now().Add(-1 * time.Hour)

	mas.addUser("u-stale-unclaimed", "staleunclaimed", old) // should be locked
	mas.addUser("u-has-email", "hasemail", old)             // human awaiting review -> skip
	mas.emails["u-has-email"] = "human@example.com"
	mas.addUser("u-verified", "verifieduser", old)                         // verified -> skip
	mas.addUser("u-excluded", "excludedbot", old)                          // defensive exclusion -> skip
	mas.addUser("u-young", "younguser", young)                             // not stale yet -> skip
	alreadyLocked := mas.addUser("u-already-locked", "alreadylocked", old) // already locked -> skip
	lockedAt := old.Add(time.Minute)
	alreadyLocked.lockedAt = &lockedAt
	deactivated := mas.addUser("u-deactivated", "deactivateduser", old) // deactivated -> skip
	deactivatedAt := old.Add(time.Minute)
	deactivated.deactivatedAt = &deactivatedAt

	store := newFakeStore()
	store.verified["@verifieduser:"+serverName] = true

	cfg := Config{
		LockAfterHours: 48,
		ExcludeMXIDs:   map[string]bool{"@excludedbot:" + serverName: true},
		OwnerEmail:     "", // digest not under test here
	}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if got, want := mas.lockCalls, []string{"u-stale-unclaimed"}; !equalStrSlices(got, want) {
		t.Errorf("lockCalls = %v, want %v", got, want)
	}
}

func TestSweep_PreLockRecheckProtectsNewGrant(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-newly-verified", "newlyverified", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	mxid := "@newlyverified:" + serverName
	// VerifiedMXIDs takes an empty sweep-start snapshot. The per-account read represents a grant
	// committed after that snapshot but before janitor reaches the candidate.
	store.queueVerification(mxid, verificationResult{verified: true})

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mas.lockCalls) != 0 {
		t.Errorf("lockCalls = %v, want none after fresh verification", mas.lockCalls)
	}
}

func TestSweep_PreLockRecheckErrorRefusesToLock(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-db-uncertain", "dbuncertain", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	store.queueVerification("@dbuncertain:"+serverName, verificationResult{err: errors.New("database unavailable")})

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mas.lockCalls) != 0 {
		t.Errorf("lockCalls = %v, want none when verification cannot be proved", mas.lockCalls)
	}
}

func TestSweep_PreLockIntentFailureRefusesToLock(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-intent-failure", "intentfailure", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	store.beginErr = errors.New("database unavailable")

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mas.lockCalls) != 0 {
		t.Errorf("lockCalls = %v, want none without durable intent", mas.lockCalls)
	}
}

func TestSweep_UnlocksVerifiedAccountFoundLocked(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	user := mas.addUser("u-entitled-locked", "entitledlocked", time.Now().Add(-72*time.Hour))
	lockedAt := time.Now().Add(-time.Hour)
	user.lockedAt = &lockedAt

	store := newFakeStore()
	store.setVerified("@entitledlocked:"+serverName, true)
	store.setJanitorLocked("u-entitled-locked", lockedAt)

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got, want := mas.unlockCalls, []string{"u-entitled-locked"}; !equalStrSlices(got, want) {
		t.Errorf("unlockCalls = %v, want %v", got, want)
	}
	if len(mas.lockCalls) != 0 {
		t.Errorf("lockCalls = %v, want none", mas.lockCalls)
	}
	if user.lockedAt != nil {
		t.Error("verified janitor-owned account remained locked after repair")
	}
}

func TestSweep_DoesNotReverseExternalLockOnVerifiedAccount(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	user := mas.addUser("u-externally-locked", "externallylocked", time.Now().Add(-72*time.Hour))
	lockedAt := time.Now().Add(-time.Hour)
	user.lockedAt = &lockedAt

	store := newFakeStore()
	store.setVerified("@externallylocked:"+serverName, true)
	store.setJanitorLocked("u-externally-locked", lockedAt.Add(-time.Hour))

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mas.unlockCalls) != 0 {
		t.Errorf("unlockCalls = %v, want none for a lock without janitor provenance", mas.unlockCalls)
	}
	if user.lockedAt == nil {
		t.Error("external/operator lock was erased")
	}
	if _, found := store.janitorLocks["u-externally-locked"]; found {
		t.Error("stale janitor provenance was not cleared for the newer external lock")
	}
}

func TestSweep_LeavesUnverifiedJanitorAccountLocked(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	user := mas.addUser("u-unverified-locked", "unverifiedlocked", time.Now().Add(-72*time.Hour))
	lockedAt := time.Now().Add(-time.Hour)
	user.lockedAt = &lockedAt

	store := newFakeStore()
	store.setJanitorLocked("u-unverified-locked", lockedAt)
	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mas.unlockCalls) != 0 {
		t.Errorf("unlockCalls = %v, want none", mas.unlockCalls)
	}
	if user.lockedAt == nil {
		t.Error("unverified janitor-owned account unexpectedly became unlocked")
	}
}

func TestSweep_DoesNotUnlockDeactivatedVerifiedAccount(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	user := mas.addUser("u-deactivated-entitled", "deactivatedentitled", time.Now().Add(-72*time.Hour))
	lockedAt := time.Now().Add(-time.Hour)
	deactivatedAt := time.Now().Add(-2 * time.Hour)
	user.lockedAt = &lockedAt
	user.deactivatedAt = &deactivatedAt

	store := newFakeStore()
	store.setVerified("@deactivatedentitled:"+serverName, true)
	store.setJanitorLocked("u-deactivated-entitled", lockedAt)

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mas.unlockCalls) != 0 {
		t.Errorf("unlockCalls = %v, want none for deactivated account", mas.unlockCalls)
	}
	if user.lockedAt == nil {
		t.Error("deactivated account's independent lock was erased")
	}
	if _, found := store.janitorLocks["u-deactivated-entitled"]; found {
		t.Fatal("deactivation did not permanently relinquish janitor lock provenance")
	}

	// Reactivation must not revive janitor ownership of the still-present lock.
	user.deactivatedAt = nil
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep after reactivation: %v", err)
	}
	if len(mas.unlockCalls) != 0 {
		t.Errorf("unlockCalls after reactivation = %v, want none", mas.unlockCalls)
	}
	if user.lockedAt == nil {
		t.Error("reactivated account's operator-owned lock was erased")
	}
}

func TestSweep_CompensatesWhenGrantAppearsDuringLock(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-raced-grant", "racedgrant", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	mxid := "@racedgrant:" + serverName
	mas.afterLock = func() { store.setVerified(mxid, true) }

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got, want := mas.lockCalls, []string{"u-raced-grant"}; !equalStrSlices(got, want) {
		t.Errorf("lockCalls = %v, want %v", got, want)
	}
	if got, want := mas.unlockCalls, []string{"u-raced-grant"}; !equalStrSlices(got, want) {
		t.Errorf("unlockCalls = %v, want compensating %v", got, want)
	}
	if mas.users[0].lockedAt != nil {
		t.Error("account remained locked after compensating unlock")
	}
}

func TestSweep_PostLockVerificationErrorCompensates(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-post-lock-uncertain", "postlockuncertain", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	mxid := "@postlockuncertain:" + serverName
	store.queueVerification(mxid,
		verificationResult{verified: false},
		verificationResult{err: errors.New("database unavailable")},
	)

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got, want := mas.lockCalls, []string{"u-post-lock-uncertain"}; !equalStrSlices(got, want) {
		t.Errorf("lockCalls = %v, want %v", got, want)
	}
	if got, want := mas.unlockCalls, []string{"u-post-lock-uncertain"}; !equalStrSlices(got, want) {
		t.Errorf("unlockCalls = %v, want compensating %v", got, want)
	}
	if mas.users[0].lockedAt != nil {
		t.Error("account remained locked after uncertain post-lock read")
	}
}

func TestSweep_ConfirmationFailureRetainsIntentAndConverges(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	user := mas.addUser("u-confirmation-failure", "confirmationfailure", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	store.confirmErr = errors.New("database unavailable")

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("first Sweep: %v", err)
	}
	if got, want := mas.lockCalls, []string{"u-confirmation-failure"}; !equalStrSlices(got, want) {
		t.Errorf("lockCalls = %v, want %v", got, want)
	}
	if user.lockedAt == nil {
		t.Fatal("confirmation failure did not leave the successfully locked account locked")
	}
	if _, found := store.pendingLocks["u-confirmation-failure"]; !found {
		t.Fatal("pre-lock intent was lost after confirmation failure")
	}

	store.confirmErr = nil
	store.setVerified("@confirmationfailure:"+serverName, true)
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if user.lockedAt != nil {
		t.Error("pending lock did not converge after confirmation recovered")
	}
	if _, found := store.pendingLocks["u-confirmation-failure"]; found {
		t.Error("pending intent remained after convergence")
	}
}

func TestSweep_FailedCompensationConvergesOnNextSweep(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	user := mas.addUser("u-retry-unlock", "retryunlock", time.Now().Add(-72*time.Hour))
	mas.unlockFailures = 1

	store := newFakeStore()
	mxid := "@retryunlock:" + serverName
	mas.afterLock = func() { store.setVerified(mxid, true) }

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("first Sweep: %v", err)
	}
	if user.lockedAt == nil {
		t.Fatal("injected unlock failure did not leave the account locked")
	}

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if user.lockedAt != nil {
		t.Error("janitor-owned verified lock did not converge on the next sweep")
	}
	if got, want := mas.unlockCalls, []string{"u-retry-unlock", "u-retry-unlock"}; !equalStrSlices(got, want) {
		t.Errorf("unlockCalls = %v, want failed attempt then repair %v", got, want)
	}
}

func TestSweep_AmbiguousLockResponseConvergesFromIntent(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	user := mas.addUser("u-ambiguous-lock", "ambiguouslock", time.Now().Add(-72*time.Hour))
	mas.lockResponseFailures = 1

	store := newFakeStore()
	mxid := "@ambiguouslock:" + serverName
	mas.afterLock = func() { store.setVerified(mxid, true) }

	cfg := Config{LockAfterHours: 48}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("first Sweep: %v", err)
	}
	if user.lockedAt == nil {
		t.Fatal("injected post-commit response failure did not leave MAS locked")
	}
	if _, found := store.pendingLocks["u-ambiguous-lock"]; !found {
		t.Fatal("ambiguous lock lost its durable pre-call intent")
	}

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if user.lockedAt != nil {
		t.Error("ambiguous committed lock did not converge on the next sweep")
	}
	if got, want := mas.unlockCalls, []string{"u-ambiguous-lock"}; !equalStrSlices(got, want) {
		t.Errorf("unlockCalls = %v, want %v", got, want)
	}
}

// TestSweep_DryRunLocksNothing proves DRY_RUN takes no action even when accounts would otherwise
// qualify.
func TestSweep_DryRunLocksNothing(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-stale-unclaimed", "staleunclaimed", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	cfg := Config{LockAfterHours: 48, DryRun: true}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mas.lockCalls) != 0 {
		t.Errorf("lockCalls = %v, want none (DRY_RUN)", mas.lockCalls)
	}
}

func TestSweep_DryRunDoesNotDeleteStaleProvenance(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-dry-run-stale-record", "dryrunstalerecord", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	store.setJanitorLocked("u-dry-run-stale-record", time.Now().Add(-time.Hour))
	cfg := Config{LockAfterHours: 48, DryRun: true}
	sweeper, _ := newSweeperForTest(t, mas, store, LogMailer{}, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if _, found := store.janitorLocks["u-dry-run-stale-record"]; !found {
		t.Error("dry run deleted persisted janitor lock provenance")
	}
	if len(mas.lockCalls) != 0 || len(mas.unlockCalls) != 0 {
		t.Errorf("dry run mutated MAS: lockCalls=%v unlockCalls=%v", mas.lockCalls, mas.unlockCalls)
	}
}

// TestSweep_Digest_SendsOnlyAccountsAfterHighWaterMarkAndAdvancesIt covers the digest half:
// existing (already-reported) email accounts are excluded, new ones are included, and the
// high-water mark advances to the newest reported account's created_at only after a successful
// send.
func TestSweep_Digest_SendsOnlyAccountsAfterHighWaterMarkAndAdvancesIt(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	mas.addUser("u-old-reported", "oldreported", base)
	mas.emails["u-old-reported"] = "old@example.com"

	mas.addUser("u-new-1", "newone", base.Add(time.Hour))
	mas.emails["u-new-1"] = "new1@example.com"

	mas.addUser("u-new-2", "newtwo", base.Add(2*time.Hour))
	mas.emails["u-new-2"] = "new2@example.com"

	mas.addUser("u-no-email", "noemailhuman", base.Add(3*time.Hour)) // no email -> not a digest candidate

	store := newFakeStore()
	store.highWater["digest_high_water"] = base.Add(30 * time.Minute) // u-old-reported already covered

	mailer := &fakeMailer{}
	cfg := Config{LockAfterHours: 48, OwnerEmail: "owner@telecrypt.io"}
	sweeper, _ := newSweeperForTest(t, mas, store, mailer, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if len(mailer.sends) != 1 {
		t.Fatalf("mailer sends = %d, want 1", len(mailer.sends))
	}
	if mailer.lastTo != "owner@telecrypt.io" {
		t.Errorf("digest sent to %q, want owner@telecrypt.io", mailer.lastTo)
	}
	if want := "@newone:" + serverName; !strings.Contains(mailer.lastBody, want) {
		t.Errorf("digest body missing %q:\n%s", want, mailer.lastBody)
	}
	if want := "@newtwo:" + serverName; !strings.Contains(mailer.lastBody, want) {
		t.Errorf("digest body missing %q:\n%s", want, mailer.lastBody)
	}
	if strings.Contains(mailer.lastBody, "@oldreported:"+serverName) {
		t.Errorf("digest body must not include the already-reported account:\n%s", mailer.lastBody)
	}
	if strings.Contains(mailer.lastBody, "@noemailhuman:"+serverName) {
		t.Errorf("digest body must not include the email-less account:\n%s", mailer.lastBody)
	}

	wantMark := base.Add(2 * time.Hour)
	gotMark := store.highWater["digest_high_water"]
	if !gotMark.Equal(wantMark) {
		t.Errorf("high-water mark = %v, want %v", gotMark, wantMark)
	}
}

// TestSweep_Digest_FailedSendDoesNotAdvanceMark proves the "duplicates at the boundary are
// acceptable, losses are not" contract: a send failure must not advance the high-water mark, so
// the same window is retried on the next sweep.
func TestSweep_Digest_FailedSendDoesNotAdvanceMark(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-new", "newhuman", time.Now())
	mas.emails["u-new"] = "new@example.com"

	store := newFakeStore()
	mailer := &fakeMailer{sendErr: errors.New("smtp: connection refused")}
	cfg := Config{LockAfterHours: 48, OwnerEmail: "owner@telecrypt.io"}
	sweeper, _ := newSweeperForTest(t, mas, store, mailer, cfg)

	// Sweep itself doesn't return an error for a digest failure -- it's independent of the lock
	// half and logged, not fatal (see sweep.go's Sweep doc comment).
	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if _, found := store.highWater["digest_high_water"]; found {
		t.Errorf("high-water mark should not be set after a failed send, got %v", store.highWater)
	}
}

// TestSweep_Digest_DryRunSendsNothingAndDoesNotAdvanceMark.
func TestSweep_Digest_DryRunSendsNothingAndDoesNotAdvanceMark(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-new", "newhuman", time.Now())
	mas.emails["u-new"] = "new@example.com"

	store := newFakeStore()
	mailer := &fakeMailer{}
	cfg := Config{LockAfterHours: 48, OwnerEmail: "owner@telecrypt.io", DryRun: true}
	sweeper, _ := newSweeperForTest(t, mas, store, mailer, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mailer.sends) != 0 {
		t.Errorf("mailer sends = %d, want 0 (dry run)", len(mailer.sends))
	}
	if _, found := store.highWater["digest_high_water"]; found {
		t.Errorf("high-water mark should not be set on a dry run, got %v", store.highWater)
	}
}

// TestSweep_Digest_NoOwnerEmailSkipsDigestButStillLocks proves the two halves are independent in
// the other direction: an unset OWNER_EMAIL disables the digest but the lock half still runs.
func TestSweep_Digest_NoOwnerEmailSkipsDigestButStillLocks(t *testing.T) {
	mas := newFakeMAS("locker-client", "s3cr3t")
	mas.addUser("u-stale-unclaimed", "staleunclaimed", time.Now().Add(-72*time.Hour))

	store := newFakeStore()
	mailer := &fakeMailer{}
	cfg := Config{LockAfterHours: 48, OwnerEmail: ""}
	sweeper, _ := newSweeperForTest(t, mas, store, mailer, cfg)

	if err := sweeper.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(mailer.sends) != 0 {
		t.Errorf("mailer sends = %d, want 0 (no OWNER_EMAIL)", len(mailer.sends))
	}
	if got, want := mas.lockCalls, []string{"u-stale-unclaimed"}; !equalStrSlices(got, want) {
		t.Errorf("lockCalls = %v, want %v (lock half must still run)", got, want)
	}
}

func equalStrSlices(a, b []string) bool {
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
