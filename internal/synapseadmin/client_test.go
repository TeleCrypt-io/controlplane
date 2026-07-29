package synapseadmin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserExistsEscapesMXIDAndAuthenticates(t *testing.T) {
	var escapedPath, authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escapedPath = r.URL.EscapedPath()
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "admin-token")
	exists, err := client.UserExists(context.Background(), "@bot/one:telecrypt.io")
	if err != nil {
		t.Fatalf("UserExists: %v", err)
	}
	if !exists {
		t.Fatal("UserExists = false, want true")
	}
	if !strings.Contains(escapedPath, "%2F") {
		t.Fatalf("escaped path = %q, want encoded localpart slash", escapedPath)
	}
	if authorization != "Bearer admin-token" {
		t.Fatalf("Authorization = %q, want bearer token", authorization)
	}
}

func TestUserExistsReturnsFalseOnlyForNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "admin-token")
	exists, err := client.UserExists(context.Background(), "@missing:telecrypt.io")
	if err != nil {
		t.Fatalf("UserExists: %v", err)
	}
	if exists {
		t.Fatal("UserExists = true, want false")
	}
}

func TestSetUserTypeUsesEscapedMXIDPath(t *testing.T) {
	var escapedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escapedPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "admin-token")
	if err := client.SetUserTypeVerified(context.Background(), "@bot/one:telecrypt.io"); err != nil {
		t.Fatalf("SetUserTypeVerified: %v", err)
	}
	if !strings.Contains(escapedPath, "%2F") {
		t.Fatalf("escaped path = %q, want encoded localpart slash", escapedPath)
	}
}
