package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProvisionAgentCallsOnlyPrivateIssuer(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/agents" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		parts := splitAssertion(r.Header.Get("Authorization"))
		if len(parts) != 3 || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), mustDecode(t, parts[2])) {
			http.Error(w, "bad assertion", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Provisioned{MXID: "@agent:telecrypt.io", AccessToken: "pat", DeviceID: "AGT1", Homeserver: "https://backend.telecrypt.io"})
	}))
	defer server.Close()

	p, err := NewProvisioner(server.URL, base64.RawURLEncoding.EncodeToString(private), nil)
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	got, err := p.ProvisionAgent(context.Background())
	if err != nil {
		t.Fatalf("ProvisionAgent: %v", err)
	}
	if got.AccessToken != "pat" || got.MXID != "@agent:telecrypt.io" {
		t.Fatalf("result = %#v", got)
	}
}

func splitAssertion(value string) []string {
	const prefix = "Bearer "
	if len(value) < len(prefix) || value[:len(prefix)] != prefix {
		return nil
	}
	var out []string
	start := len(prefix)
	for i := start; i <= len(value); i++ {
		if i == len(value) || value[i] == '.' {
			out = append(out, value[start:i])
			start = i + 1
		}
	}
	return out
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
