// Package agent implements Registration's stateless public MAS flow: generate a localpart and
// password, register the account through MAS's public registration form, and obtain a Matrix
// device token through public OAuth device authorization. It has no MAS/Synapse admin authority.
package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/TeleCrypt-io/controlplane/internal/registrationfailure"
)

type Provisioned struct {
	MXID               string
	Password           string
	AccessToken        string
	RefreshToken       string
	ExpiresIn          int
	DeviceID           string
	Homeserver         string
	OAuthIssuer        string
	OAuthClientID      string
	OAuthTokenEndpoint string
}

type Provisioner struct {
	masReg           masRegClient
	backendPublicURL string // e.g. https://backend.telecrypt.io
	serverName       string // e.g. telecrypt.io — Matrix data-plane identity
}

// NewProvisioner creates a Provisioner. ServerName is required because it is the Matrix data-plane
// identity and must not silently change when the public backend origin changes.
func NewProvisioner(m masRegClient, backendPublicURL, serverName string) (*Provisioner, error) {
	if _, err := validateBackendPublicURL(backendPublicURL); err != nil {
		return nil, err
	}
	if serverName == "" {
		return nil, fmt.Errorf("server name must not be empty")
	}
	return &Provisioner{
		masReg:           m,
		backendPublicURL: backendPublicURL,
		serverName:       serverName,
	}, nil
}

func validateBackendPublicURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 8<<10 {
		return nil, fmt.Errorf("backend public URL must be non-empty and at most 8192 bytes")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("backend public URL must be an absolute origin without credentials, path, query, or fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopbackHost(u)) {
		return nil, fmt.Errorf("backend public URL must use HTTPS (HTTP is allowed only for loopback tests)")
	}
	return u, nil
}

func isLoopbackHost(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ProvisionAgent generates a random localpart/password, registers through MAS's public form,
// and returns the password only to the immediate Registration caller along with a refreshable OAuth
// token set. It never persists or logs any credential.
func (p *Provisioner) ProvisionAgent(ctx context.Context) (*Provisioned, error) {
	localpart, err := randomLocalpart()
	if err != nil {
		return nil, registrationfailure.Wrap(registrationfailure.StageLocalGeneration, fmt.Errorf("generate localpart: %w", err))
	}
	mxid := fmt.Sprintf("@%s:%s", localpart, p.serverName)

	password, err := randomPassword()
	if err != nil {
		return nil, registrationfailure.Wrap(registrationfailure.StageLocalGeneration, fmt.Errorf("generate password: %w", err))
	}

	deviceID, err := randomDeviceID()
	if err != nil {
		return nil, registrationfailure.Wrap(registrationfailure.StageLocalGeneration, fmt.Errorf("generate device id: %w", err))
	}

	tokens, err := p.masReg.RegisterAndAuthorizeDevice(ctx, localpart, password, deviceID, p.backendPublicURL)
	if err != nil {
		return nil, registrationfailure.Wrap(registrationfailure.StageInternal, fmt.Errorf("MAS public registration and OAuth device authorization: %w", err))
	}
	if tokens == nil {
		return nil, registrationfailure.WithKind(registrationfailure.StageInternal, registrationfailure.KindInvariant, errors.New("MAS registration returned no token set"))
	}
	if tokens.UserID != mxid {
		return nil, registrationfailure.WithKind(registrationfailure.StageIdentity, registrationfailure.KindInvariant, errors.New("OAuth token returned unexpected user_id"))
	}

	return &Provisioned{
		MXID:               mxid,
		Password:           password,
		AccessToken:        tokens.AccessToken,
		RefreshToken:       tokens.RefreshToken,
		ExpiresIn:          tokens.ExpiresIn,
		DeviceID:           deviceID,
		Homeserver:         p.backendPublicURL,
		OAuthIssuer:        tokens.Issuer,
		OAuthClientID:      tokens.ClientID,
		OAuthTokenEndpoint: tokens.TokenEndpoint,
	}, nil
}
