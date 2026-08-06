package masadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUser is the fakeMASAdmin server's in-memory notion of one MAS account.
type fakeUser struct {
	id        string
	username  string
	createdAt time.Time
	lockedAt  *time.Time
	admin     bool
}

// fakeMASAdmin reproduces just enough of MAS 1.16.0's admin API — POST /oauth2/token
// (client_credentials, Basic-auth-only), GET /api/admin/v1/users and /user-emails (cursor
// pagination via page[first]/page[after]), and POST /api/admin/v1/users/{id}/{lock,unlock} — to
// exercise Client's HTTP mechanics end-to-end. See client.go's package doc for the MAS source
// files this is modeled on.
type fakeMASAdmin struct {
	clientID       string
	clientSecret   string
	tokenExpiresIn int // seconds

	mu           sync.Mutex
	tokenFetches int
	users        []*fakeUser
	emails       map[string]string // user id -> email
}

func newFakeMASAdmin(clientID, clientSecret string) *fakeMASAdmin {
	return &fakeMASAdmin{
		clientID:       clientID,
		clientSecret:   clientSecret,
		tokenExpiresIn: 300,
		emails:         map[string]string{},
	}
}

func (f *fakeMASAdmin) addUser(id, username string, createdAt time.Time, locked bool) *fakeUser {
	u := &fakeUser{id: id, username: username, createdAt: createdAt}
	if locked {
		t := createdAt.Add(time.Hour)
		u.lockedAt = &t
	}
	f.mu.Lock()
	f.users = append(f.users, u)
	f.mu.Unlock()
	return u
}

func (f *fakeMASAdmin) addEmail(userID, email string) {
	f.mu.Lock()
	f.emails[userID] = email
	f.mu.Unlock()
}

func (f *fakeMASAdmin) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/token", f.handleToken)
	mux.HandleFunc("GET /api/admin/v1/users", f.handleListUsers)
	mux.HandleFunc("GET /api/admin/v1/user-emails", f.handleListEmails)
	mux.HandleFunc("POST /api/admin/v1/users/{id}/lock", f.handleLock)
	mux.HandleFunc("POST /api/admin/v1/users/{id}/unlock", f.handleUnlock)
	mux.HandleFunc("POST /api/admin/v1/users", f.handleCreateUser)
	mux.HandleFunc("POST /api/admin/v1/users/{id}/deactivate", f.handleDeactivate)
	mux.HandleFunc("POST /api/admin/v1/personal-sessions", f.handleCreatePersonalSession)
	return httptest.NewServer(mux)
}

func (f *fakeMASAdmin) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	var input struct {
		Username string `json:"username"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || input.Username == "" {
		http.Error(w, "bad user", http.StatusBadRequest)
		return
	}
	created := f.addUser("01CREATEDUSER0000000000000", input.Username, time.Now().UTC(), false)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": "user", "id": created.id, "attributes": fakeUserAttrs{Username: created.username, CreatedAt: created.createdAt}}}) //nolint:errcheck
}

func (f *fakeMASAdmin) handleCreatePersonalSession(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	var input struct {
		ActorUserID string  `json:"actor_user_id"`
		HumanName   string  `json:"human_name"`
		Scope       string  `json:"scope"`
		ExpiresIn   *uint32 `json:"expires_in"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || input.ActorUserID == "" || input.HumanName == "" || input.Scope == "" || input.ExpiresIn != nil {
		http.Error(w, "bad session", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": "personal-session", "id": "01PERSONALSESSION000000000", "attributes": map[string]any{"access_token": "mas_pat_test"}}}) //nolint:errcheck
}

func (f *fakeMASAdmin) handleDeactivate(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": "user", "id": r.PathValue("id"), "attributes": map[string]any{}}}) //nolint:errcheck
}

func (f *fakeMASAdmin) handleToken(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != f.clientID || pass != f.clientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"title":"invalid_client"}]}`)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"title":"unsupported grant_type"}]}`)
		return
	}
	if r.PostForm.Get("scope") != "urn:mas:admin" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"title":"unexpected scope"}]}`)
		return
	}
	// Real MAS rejects client_secret in the POST body for a client_secret_basic-registered client
	// (see client.go's package doc). Enforcing that here too catches a regression to sending
	// creds via the body instead of the Authorization header.
	if r.PostForm.Get("client_secret") != "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"title":"invalid_client: expected Basic auth, not POST body"}]}`)
		return
	}

	f.mu.Lock()
	f.tokenFetches++
	n := f.tokenFetches
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"test-token-%d","token_type":"Bearer","expires_in":%d}`, n, f.tokenExpiresIn)
}

func (f *fakeMASAdmin) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer test-token-") {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

type fakeUserAttrs struct {
	Username      string     `json:"username"`
	CreatedAt     time.Time  `json:"created_at"`
	LockedAt      *time.Time `json:"locked_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
	Admin         bool       `json:"admin"`
	LegacyGuest   bool       `json:"legacy_guest"`
}

type fakeEmailAttrs struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
}

type fakeResource[T any] struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes T      `json:"attributes"`
}

func writePage[T any](w http.ResponseWriter, data []fakeResource[T], hasNext bool) {
	resp := struct {
		Data  []fakeResource[T] `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links"`
	}{Data: data}
	if hasNext {
		resp.Links.Next = "has-more" // Client only checks presence, never parses this URL
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// paginate slices sorted (by id, ascending -- matching real MAS's UserFilter ordering) according
// to page[first]/page[after] query params, mirroring admin/params.rs's contract.
func paginate[T any](r *http.Request, ids []string, first int) (start, end int, hasNext bool) {
	if v := r.URL.Query().Get("page[first]"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			first = n
		}
	}
	start = 0
	if after := r.URL.Query().Get("page[after]"); after != "" {
		for i, id := range ids {
			if id == after {
				start = i + 1
				break
			}
		}
	}
	end = start + first
	if end > len(ids) {
		end = len(ids)
	}
	if start > len(ids) {
		start = len(ids)
	}
	hasNext = end < len(ids)
	return start, end, hasNext
}

func (f *fakeMASAdmin) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	sorted := append([]*fakeUser(nil), f.users...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].id < sorted[j].id })
	ids := make([]string, len(sorted))
	for i, u := range sorted {
		ids[i] = u.id
	}

	start, end, hasNext := paginate[fakeUserAttrs](r, ids, 10)

	data := make([]fakeResource[fakeUserAttrs], 0, end-start)
	for _, u := range sorted[start:end] {
		data = append(data, fakeResource[fakeUserAttrs]{
			Type: "user",
			ID:   u.id,
			Attributes: fakeUserAttrs{
				Username:  u.username,
				CreatedAt: u.createdAt,
				LockedAt:  u.lockedAt,
				Admin:     u.admin,
			},
		})
	}
	writePage(w, data, hasNext)
}

func (f *fakeMASAdmin) handleListEmails(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	type entry struct {
		id, userID, email string
	}
	var entries []entry
	i := 0
	for userID, email := range f.emails {
		entries = append(entries, entry{id: fmt.Sprintf("email-%04d", i), userID: userID, email: email})
		i++
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.id
	}

	start, end, hasNext := paginate[fakeEmailAttrs](r, ids, 10)

	data := make([]fakeResource[fakeEmailAttrs], 0, end-start)
	for _, e := range entries[start:end] {
		data = append(data, fakeResource[fakeEmailAttrs]{
			Type: "user-email",
			ID:   e.id,
			Attributes: fakeEmailAttrs{
				CreatedAt: time.Now().UTC(),
				UserID:    e.userID,
				Email:     e.email,
			},
		})
	}
	writePage(w, data, hasNext)
}

func (f *fakeMASAdmin) handleLock(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	id := r.PathValue("id")

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.id == id {
			if u.lockedAt == nil {
				now := time.Now().UTC()
				u.lockedAt = &now
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"data": map[string]any{
					"type": "user",
					"id":   u.id,
					"attributes": map[string]any{
						"username":   u.username,
						"created_at": u.createdAt,
						"locked_at":  u.lockedAt,
					},
				},
			})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{"errors":[{"title":"User ID %s not found"}]}`, id)
}

func (f *fakeMASAdmin) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	id := r.PathValue("id")

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.id == id {
			u.lockedAt = nil
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"data": map[string]any{
					"type": "user",
					"id":   u.id,
					"attributes": map[string]any{
						"username":   u.username,
						"created_at": u.createdAt,
						"locked_at":  u.lockedAt,
					},
				},
			})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{"errors":[{"title":"User ID %s not found"}]}`, id)
}

func TestToken_BasicAuthCachedAcrossCalls(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	ctx := context.Background()

	if _, err := c.ListUsers(ctx); err != nil {
		t.Fatalf("first ListUsers: %v", err)
	}
	if _, err := c.ListUsers(ctx); err != nil {
		t.Fatalf("second ListUsers: %v", err)
	}

	if fake.tokenFetches != 1 {
		t.Errorf("tokenFetches = %d, want 1 (token should be cached across calls)", fake.tokenFetches)
	}
}

func TestPasswordlessUserAndPersonalSession(t *testing.T) {
	fake := newFakeMASAdmin("issuer-client", "secret")
	srv := fake.server()
	defer srv.Close()
	c := NewClient(srv.URL, "issuer-client", "secret")
	user, err := c.CreateUser(context.Background(), "agent123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Username != "agent123" || user.ID == "" {
		t.Fatalf("user = %#v", user)
	}
	session, err := c.CreatePersonalSession(context.Background(), user.ID, "TeleCrypt agent", "urn:matrix:test", nil)
	if err != nil {
		t.Fatalf("CreatePersonalSession: %v", err)
	}
	if session.AccessToken != "mas_pat_test" {
		t.Fatalf("session = %#v", session)
	}
	if err := c.DeactivateUser(context.Background(), user.ID); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}
}

func TestToken_RefetchesNearExpiry(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	fake.tokenExpiresIn = 1 // well under tokenSafetyMargin, forces a refetch every call
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := c.ListUsers(ctx); err != nil {
			t.Fatalf("ListUsers call %d: %v", i, err)
		}
	}

	if fake.tokenFetches != 3 {
		t.Errorf("tokenFetches = %d, want 3 (a ~1s-TTL token should be refetched every call)", fake.tokenFetches)
	}
}

func TestToken_WrongCredentialsFails(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "locker-client", "wrong-secret")
	if _, err := c.ListUsers(context.Background()); err == nil {
		t.Fatal("expected an error with the wrong client secret")
	}
}

func TestListUsers_Pagination(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	const n = 2*listPageSize + 7 // forces three pages at the client's fixed page size
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		fake.addUser(fmt.Sprintf("user-%05d", i), fmt.Sprintf("agent%05d", i), base.Add(time.Duration(i)*time.Minute), false)
	}

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	got, err := c.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d users, want %d", len(got), n)
	}

	seen := make(map[string]bool, n)
	for _, u := range got {
		seen[u.ID] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct user IDs, want %d (pagination must not duplicate or drop)", len(seen), n)
	}
}

func TestListUserEmails(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	fake.addUser("user-1", "alice", time.Now(), false)
	fake.addUser("user-2", "bob-agent", time.Now(), false)
	fake.addEmail("user-1", "alice@example.com")

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	got, err := c.ListUserEmails(context.Background())
	if err != nil {
		t.Fatalf("ListUserEmails: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d emails, want 1", len(got))
	}
	if got[0].UserID != "user-1" || got[0].Email != "alice@example.com" {
		t.Errorf("got %+v, want user_id=user-1 email=alice@example.com", got[0])
	}
}

func TestLockUser(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	fake.addUser("user-1", "stale-agent", time.Now().Add(-72*time.Hour), false)

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	ctx := context.Background()

	lockedAt, err := c.LockUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	if lockedAt.IsZero() {
		t.Fatal("LockUser returned a zero locked_at timestamp")
	}

	users, err := c.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers after lock: %v", err)
	}
	if len(users) != 1 || users[0].LockedAt == nil {
		t.Fatalf("expected user-1 to be locked, got %+v", users)
	}
}

func TestLockUser_NotFound(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	_, err := c.LockUser(context.Background(), "no-such-user")
	if err == nil {
		t.Fatal("expected an error locking an unknown user ID")
	}
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("error = %v, want errors.Is(..., ErrUserNotFound)", err)
	}
}

func TestUnlockUser(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	fake.addUser("user-1", "entitled-agent", time.Now().Add(-72*time.Hour), true)

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	ctx := context.Background()

	if err := c.UnlockUser(ctx, "user-1"); err != nil {
		t.Fatalf("UnlockUser: %v", err)
	}

	users, err := c.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers after unlock: %v", err)
	}
	if len(users) != 1 || users[0].LockedAt != nil {
		t.Fatalf("expected user-1 to be unlocked, got %+v", users)
	}
}

func TestUnlockUser_NotFound(t *testing.T) {
	fake := newFakeMASAdmin("locker-client", "s3cr3t")
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL, "locker-client", "s3cr3t")
	err := c.UnlockUser(context.Background(), "no-such-user")
	if err == nil {
		t.Fatal("expected an error unlocking an unknown user ID")
	}
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("error = %v, want errors.Is(..., ErrUserNotFound)", err)
	}
}
