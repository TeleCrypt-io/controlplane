package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TeleCrypt-io/controlplane/internal/masreg"
	"github.com/TeleCrypt-io/controlplane/internal/synapse"
)

// fakeMASReg is a fake masreg.Client for unit-testing Provisioner's control flow in isolation
// from the HTTP mechanics (those are covered by internal/masreg's own tests and by
// TestProvisionAgent_EndToEndAgainstFakeMAS below).
type fakeMASReg struct {
	registerErr error
	registered  map[string]string // username -> password
}

func newFakeMASReg() *fakeMASReg {
	return &fakeMASReg{registered: map[string]string{}}
}

func (f *fakeMASReg) Register(ctx context.Context, username, password string) error {
	if f.registerErr != nil {
		return f.registerErr
	}
	f.registered[username] = password
	return nil
}

// fakeSynapse is a fake Synapse client.
type fakeSynapse struct {
	loginErrs   []error
	loginUserID string // if empty, echoes back whatever was requested correctly
	loginCalls  int
}

func (f *fakeSynapse) CompatLogin(ctx context.Context, username, password, deviceID string) (*synapse.LoginResult, error) {
	f.loginCalls++
	if len(f.loginErrs) != 0 {
		err := f.loginErrs[0]
		f.loginErrs = f.loginErrs[1:]
		return nil, err
	}
	userID := f.loginUserID
	if userID == "" {
		userID = "@" + username + ":telecrypt.io"
	}
	return &synapse.LoginResult{UserID: userID, AccessToken: "mct_faketoken"}, nil
}

func TestProvisionAgent_HappyPath(t *testing.T) {
	m := newFakeMASReg()
	sy := &fakeSynapse{}

	p, err := NewProvisioner(m, sy, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	result, err := p.ProvisionAgent(context.Background())
	if err != nil {
		t.Fatalf("ProvisionAgent: %v", err)
	}

	if result.AccessToken != "mct_faketoken" {
		t.Errorf("access token = %q, want mct_faketoken", result.AccessToken)
	}
	if result.Homeserver != "https://telecrypt.io" {
		t.Errorf("homeserver = %q, want https://telecrypt.io", result.Homeserver)
	}
	if result.DeviceID == "" {
		t.Error("expected a non-empty device_id")
	}
	localpart := result.MXID[1 : len(result.MXID)-len(":telecrypt.io")]
	if pw, ok := m.registered[localpart]; !ok || pw == "" {
		t.Errorf("expected Register to have been called with localpart %q and a non-empty password", localpart)
	}
}

func TestProvisionAgent_RegisterFails(t *testing.T) {
	m := newFakeMASReg()
	m.registerErr = errors.New("mas unreachable")
	sy := &fakeSynapse{}

	p, err := NewProvisioner(m, sy, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	if _, err := p.ProvisionAgent(context.Background()); err == nil {
		t.Fatal("expected an error when mas registration fails")
	}
}

func TestProvisionAgent_CompatLoginFails(t *testing.T) {
	m := newFakeMASReg()
	sy := &fakeSynapse{loginErrs: []error{errors.New("synapse unreachable")}}

	p, err := NewProvisioner(m, sy, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	if _, err := p.ProvisionAgent(context.Background()); err == nil {
		t.Fatal("expected an error when compat login fails")
	}
	if sy.loginCalls != 1 {
		t.Fatalf("non-retryable login calls = %d, want 1", sy.loginCalls)
	}
}

func TestProvisionAgent_RetriesTransientCompatLoginFailure(t *testing.T) {
	m := newFakeMASReg()
	sy := &fakeSynapse{loginErrs: []error{
		&synapse.CompatLoginError{StatusCode: http.StatusInternalServerError},
		&synapse.CompatLoginError{StatusCode: http.StatusBadGateway},
	}}

	p, err := NewProvisioner(m, sy, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	if _, err := p.ProvisionAgent(context.Background()); err != nil {
		t.Fatalf("ProvisionAgent: %v", err)
	}
	if sy.loginCalls != 3 {
		t.Fatalf("login calls = %d, want 3", sy.loginCalls)
	}
}

func TestProvisionAgent_DoesNotRetryAuthenticationFailure(t *testing.T) {
	m := newFakeMASReg()
	sy := &fakeSynapse{loginErrs: []error{
		&synapse.CompatLoginError{StatusCode: http.StatusForbidden},
	}}

	p, err := NewProvisioner(m, sy, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	if _, err := p.ProvisionAgent(context.Background()); err == nil {
		t.Fatal("expected an error when compat login is forbidden")
	}
	if sy.loginCalls != 1 {
		t.Fatalf("login calls = %d, want 1", sy.loginCalls)
	}
}

func TestProvisionAgent_CompatLoginRetryHonorsContext(t *testing.T) {
	m := newFakeMASReg()
	sy := &fakeSynapse{loginErrs: []error{
		&synapse.CompatLoginError{StatusCode: http.StatusInternalServerError},
		&synapse.CompatLoginError{StatusCode: http.StatusInternalServerError},
	}}

	p, err := NewProvisioner(m, sy, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ProvisionAgent(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ProvisionAgent error = %v, want context canceled", err)
	}
	if sy.loginCalls != 1 {
		t.Fatalf("login calls = %d, want 1", sy.loginCalls)
	}
}

// TestProvisionAgent_CompatLoginReturnsWrongUser guards the identity-model assumption itself:
// if MAS and Synapse ever disagree on the MXID, we must fail closed rather than hand out a token
// for the wrong account.
func TestProvisionAgent_CompatLoginReturnsWrongUser(t *testing.T) {
	m := newFakeMASReg()
	sy := &fakeSynapse{loginUserID: "@someone-else:telecrypt.io"}

	p, err := NewProvisioner(m, sy, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	if _, err := p.ProvisionAgent(context.Background()); err == nil {
		t.Fatal("expected an error when compat login's user_id doesn't match the mxid we registered")
	}
}

// --- end-to-end against a fake MAS (registration form flow + compat login) ---

// fakeMASServer combines a minimal MAS public-registration form flow (mirroring
// internal/masreg's fake, see its client_test.go for the source-derived contract this models)
// with the compat login endpoint, so ProvisionAgent can be exercised against one httptest server
// exactly the way it will run against the real MAS/Synapse stack.
type fakeMASServer struct {
	csrf  string
	regID string

	users map[string]string // username -> password, populated once registration completes
}

func newFakeMASServer() *fakeMASServer {
	return &fakeMASServer{csrf: "e2e-csrf-token", regID: "01E2EREG", users: map[string]string{}}
}

func (f *fakeMASServer) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /register", f.registerGet)
	mux.HandleFunc("GET /register/password", f.passwordGet)
	mux.HandleFunc("POST /register/password", f.passwordPost)
	mux.HandleFunc("GET /register/steps/{id}/finish", f.finishGet)
	mux.HandleFunc("GET /register/steps/{id}/display-name", f.displayNameGet)
	mux.HandleFunc("POST /register/steps/{id}/display-name", f.displayNamePost)
	mux.HandleFunc("GET /", f.index)
	mux.HandleFunc("POST /_matrix/client/v3/login", f.compatLogin)
	return httptest.NewServer(mux)
}

func (f *fakeMASServer) setCSRF(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "csrf", Value: f.csrf, Path: "/"})
}

func (f *fakeMASServer) render(w http.ResponseWriter, extra string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<html><body><form method="POST"><input type="hidden" name="csrf" value="` + f.csrf + `" />` + extra + `</form></body></html>`))
}

func (f *fakeMASServer) registerGet(w http.ResponseWriter, r *http.Request) {
	f.setCSRF(w)
	http.Redirect(w, r, "/register/password", http.StatusSeeOther)
}

func (f *fakeMASServer) passwordGet(w http.ResponseWriter, r *http.Request) {
	f.setCSRF(w)
	f.render(w, "")
}

func (f *fakeMASServer) passwordPost(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("csrf") != f.csrf {
		http.Error(w, "bad csrf", http.StatusBadRequest)
		return
	}
	f.users[r.FormValue("username")] = r.FormValue("password")
	http.Redirect(w, r, "/register/steps/"+f.regID+"/finish", http.StatusSeeOther)
}

func (f *fakeMASServer) finishGet(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/register/steps/"+f.regID+"/display-name", http.StatusSeeOther)
}

func (f *fakeMASServer) displayNameGet(w http.ResponseWriter, r *http.Request) {
	f.setCSRF(w)
	f.render(w, "")
}

func (f *fakeMASServer) displayNamePost(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("csrf") != f.csrf {
		http.Error(w, "bad csrf", http.StatusBadRequest)
		return
	}
	// Real MAS redirects back to the finish step, which then completes the registration and
	// redirects away from /register; this fake collapses that into one hop straight to "/".
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (f *fakeMASServer) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("welcome"))
}

// compatLogin mirrors internal/synapse.Client.CompatLogin's request shape and rejects anything
// that doesn't match the username/password just registered — proving the two calls are actually
// chained on the same credentials, not just independently faked.
func (f *fakeMASServer) compatLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Identifier struct {
			User string `json:"user"`
		} `json:"identifier"`
		Password string `json:"password"`
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	want, ok := f.users[body.Identifier.User]
	if !ok || want != body.Password {
		http.Error(w, "invalid credentials", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"user_id":"@` + body.Identifier.User + `:telecrypt.io","access_token":"mct_e2e_token","device_id":"` + body.DeviceID + `"}`))
}

func TestProvisionAgent_EndToEndAgainstFakeMAS(t *testing.T) {
	fake := newFakeMASServer()
	srv := fake.server()
	defer srv.Close()

	masReg := masreg.NewClient(srv.URL)
	synapseClient := synapse.NewClient(srv.URL)

	p, err := NewProvisioner(masReg, synapseClient, "https://telecrypt.io", "")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	result, err := p.ProvisionAgent(context.Background())
	if err != nil {
		t.Fatalf("ProvisionAgent: %v", err)
	}
	if result.AccessToken != "mct_e2e_token" {
		t.Errorf("access token = %q, want mct_e2e_token", result.AccessToken)
	}
	if result.Homeserver != "https://telecrypt.io" {
		t.Errorf("homeserver = %q, want https://telecrypt.io", result.Homeserver)
	}
	if len(fake.users) != 1 {
		t.Errorf("expected exactly one registration to have happened, got %v", fake.users)
	}
}
