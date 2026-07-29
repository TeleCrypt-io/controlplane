package masreg

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeMAS reproduces just enough of MAS 1.16.0's public registration flow — GET/POST /register,
// POST /register/password, the display-name step, and the finish redirect — to exercise
// Client's HTTP mechanics end-to-end: a cookie-carried CSRF token that must be echoed back as a
// hidden form field, and the 303 redirect chain through the steps. See client.go's package doc
// for the MAS source files this is modeled on.
type fakeMAS struct {
	csrf  string // single active token; a real deployment mints one per browser session
	regID string

	requireEmail   bool // simulates password_registration_email_required = true
	noRedirect     bool // simulates an upstream-OAuth-provider deployment: GET /register doesn't 303
	displayNameSet bool

	gotUsername string
	gotPassword string
}

func newFakeMAS() *fakeMAS {
	return &fakeMAS{csrf: "test-csrf-token-value", regID: "01REG"}
}

func (f *fakeMAS) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /register", f.handleRegisterGet)
	mux.HandleFunc("GET /register/password", f.handlePasswordGet)
	mux.HandleFunc("POST /register/password", f.handlePasswordPost)
	mux.HandleFunc("GET /register/steps/{id}/finish", f.handleFinishGet)
	mux.HandleFunc("GET /register/steps/{id}/display-name", f.handleDisplayNameGet)
	mux.HandleFunc("POST /register/steps/{id}/display-name", f.handleDisplayNamePost)
	mux.HandleFunc("GET /", f.handleIndex)
	return httptest.NewServer(mux)
}

func (f *fakeMAS) setCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "csrf", Value: f.csrf, Path: "/"})
}

func (f *fakeMAS) verifyCSRF(r *http.Request) error {
	cookie, err := r.Cookie("csrf")
	if err != nil || cookie.Value != f.csrf {
		return fmt.Errorf("missing or stale csrf cookie")
	}
	if r.FormValue("csrf") != f.csrf {
		return fmt.Errorf("csrf form field mismatch")
	}
	return nil
}

func renderForm(w http.ResponseWriter, csrf string, extra string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<html><body><form method="POST">
<input type="hidden" name="csrf" value="%s" />
%s
</form></body></html>`, csrf, extra)
}

func (f *fakeMAS) handleRegisterGet(w http.ResponseWriter, r *http.Request) {
	// Like real MAS, an already-authenticated visitor is redirected away from the registration
	// form entirely. This is what a cookie jar shared across Register calls would trip over.
	if c, err := r.Cookie("mas_session"); err == nil && c.Value != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	f.setCSRFCookie(w)
	if f.noRedirect {
		renderForm(w, f.csrf, "<p>choose a provider or register</p>")
		return
	}
	http.Redirect(w, r, "/register/password", http.StatusSeeOther)
}

func (f *fakeMAS) handlePasswordGet(w http.ResponseWriter, r *http.Request) {
	f.setCSRFCookie(w)
	renderForm(w, f.csrf, `<input name="username"><input name="password">`)
}

func (f *fakeMAS) handlePasswordPost(w http.ResponseWriter, r *http.Request) {
	if err := f.verifyCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if f.requireEmail && r.FormValue("email") == "" {
		f.setCSRFCookie(w)
		renderForm(w, f.csrf, `<div class="text-critical font-medium">Email is required</div>`)
		return
	}
	if r.FormValue("username") == "" || r.FormValue("password") == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if r.FormValue("password") != r.FormValue("password_confirm") {
		f.setCSRFCookie(w)
		renderForm(w, f.csrf, `<div class="text-critical font-medium">Password fields don't match</div>`)
		return
	}
	f.gotUsername = r.FormValue("username")
	f.gotPassword = r.FormValue("password")
	// A successful password POST starts a fresh registration session; like real MAS (which scopes
	// step state per registration id), its display-name step starts incomplete.
	f.displayNameSet = false
	http.Redirect(w, r, fmt.Sprintf("/register/steps/%s/finish", f.regID), http.StatusSeeOther)
}

func (f *fakeMAS) handleFinishGet(w http.ResponseWriter, r *http.Request) {
	if !f.displayNameSet {
		http.Redirect(w, r, fmt.Sprintf("/register/steps/%s/display-name", f.regID), http.StatusSeeOther)
		return
	}
	// Completing a registration logs the new account in — the session cookie a shared jar would
	// then wrongly present on the next registration's GET /register.
	http.SetCookie(w, &http.Cookie{Name: "mas_session", Value: "active", Path: "/"})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (f *fakeMAS) handleDisplayNameGet(w http.ResponseWriter, r *http.Request) {
	f.setCSRFCookie(w)
	renderForm(w, f.csrf, `<input type="hidden" name="action" value="set" /><input name="display_name">`)
}

func (f *fakeMAS) handleDisplayNamePost(w http.ResponseWriter, r *http.Request) {
	if err := f.verifyCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.displayNameSet = true
	http.Redirect(w, r, fmt.Sprintf("/register/steps/%s/finish", f.regID), http.StatusSeeOther)
}

func (f *fakeMAS) handleIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "welcome")
}

func TestRegister_HappyPath(t *testing.T) {
	fake := newFakeMAS()
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.Register(context.Background(), "alice", "hunter2correcthorse"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if fake.gotUsername != "alice" {
		t.Errorf("username submitted = %q, want alice", fake.gotUsername)
	}
	if fake.gotPassword != "hunter2correcthorse" {
		t.Errorf("password submitted = %q, want hunter2correcthorse", fake.gotPassword)
	}
	if !fake.displayNameSet {
		t.Error("expected the display-name step to have been completed (action=skip)")
	}
}

// TestRegister_SequentialRegistrationsDoNotShareSession guards Register's per-call cookie-jar
// isolation: a jar reused across calls would present the first account's live MAS session cookie
// on the next GET /register, and MAS redirects an already-authenticated visitor away from the
// form instead of serving it (see handleRegisterGet).
func TestRegister_SequentialRegistrationsDoNotShareSession(t *testing.T) {
	fake := newFakeMAS()
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.Register(context.Background(), "alice", "pw-one-correcthorse"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := c.Register(context.Background(), "bob", "pw-two-correcthorse"); err != nil {
		t.Fatalf("second Register (must not see the first call's session cookie): %v", err)
	}
	if fake.gotUsername != "bob" {
		t.Errorf("username submitted by second Register = %q, want bob", fake.gotUsername)
	}
}

// TestRegister_EmailRequiredFails covers a deployment where password_registration_email_required
// is true — Register always leaves email blank, so this must fail closed with a clear error
// rather than silently retrying or guessing an email address.
func TestRegister_EmailRequiredFails(t *testing.T) {
	fake := newFakeMAS()
	fake.requireEmail = true
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.Register(context.Background(), "bob", "hunter2correcthorse")
	if err == nil {
		t.Fatal("expected an error when the deployment requires email and Register leaves it blank")
	}
	if !strings.Contains(err.Error(), "display-name") {
		t.Errorf("error = %v, want a message about failing to reach the display-name step", err)
	}
}

// TestRegister_NoPasswordRedirectErrors covers a deployment with an upstream OAuth provider
// configured alongside password registration, where GET /register renders a combined
// provider-choice page instead of 303-redirecting straight to /register/password.
func TestRegister_NoPasswordRedirectErrors(t *testing.T) {
	fake := newFakeMAS()
	fake.noRedirect = true
	srv := fake.server()
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.Register(context.Background(), "carol", "hunter2correcthorse")
	if err == nil {
		t.Fatal("expected an error when GET /register doesn't redirect to /register/password")
	}
	if !strings.Contains(err.Error(), "/register/password") {
		t.Errorf("error = %v, want a message about /register/password", err)
	}
}
