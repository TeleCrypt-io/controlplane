package agentissuer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

type fakeMAS struct {
	created     string
	deactivated string
	issueErr    error
}

func (f *fakeMAS) CreateUser(_ context.Context, username string) (masadmin.CreatedUser, error) {
	f.created = username
	return masadmin.CreatedUser{ID: "01USER", Username: username}, nil
}
func (f *fakeMAS) CreatePersonalSession(_ context.Context, userID, _, scope string, expires *uint32) (masadmin.PersonalSession, error) {
	if expires != nil {
		panic("agent PAT unexpectedly expires")
	}
	if userID != "01USER" || scope == "" {
		panic("bad session request")
	}
	return masadmin.PersonalSession{ID: "01SESSION", AccessToken: "pat"}, f.issueErr
}
func (f *fakeMAS) DeactivateUser(_ context.Context, userID string) error {
	f.deactivated = userID
	return nil
}

func TestPasswordlessProvisioningThroughSignedBoundary(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mas := &fakeMAS{}
	issuer, err := New(mas, base64.RawURLEncoding.EncodeToString(public), "https://backend.telecrypt.io", "telecrypt.io")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(issuer)
	defer httpServer.Close()
	client, err := agent.NewProvisioner(httpServer.URL, base64.RawURLEncoding.EncodeToString(private), nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ProvisionAgent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mas.created == "" || result.MXID != "@"+mas.created+":telecrypt.io" || result.AccessToken != "pat" {
		t.Fatalf("result=%#v created=%q", result, mas.created)
	}
}
