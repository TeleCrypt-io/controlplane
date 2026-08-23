// Package agent implements Redpill's stateless public MAS flow: generate a localpart and
// password, register the account through MAS's public registration form, and obtain a Matrix
// device token through public OAuth device authorization. It has no MAS/Synapse admin authority.
package agent

import (
	"context"
	"fmt"
	"net/url"
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
	u, err := url.Parse(backendPublicURL)
	if err != nil {
		return nil, fmt.Errorf("parse backend public URL: %w", err)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("backend public URL %q has no host", backendPublicURL)
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

// ProvisionAgent generates a random localpart/password, registers through MAS's public form,
// and returns the password only to the immediate Redpill caller along with a refreshable OAuth
// token set. It never persists or logs any credential.
func (p *Provisioner) ProvisionAgent(ctx context.Context) (*Provisioned, error) {
	localpart, err := randomLocalpart()
	if err != nil {
		return nil, fmt.Errorf("generate localpart: %w", err)
	}
	mxid := fmt.Sprintf("@%s:%s", localpart, p.serverName)

	password, err := randomPassword()
	if err != nil {
		return nil, fmt.Errorf("generate password: %w", err)
	}

	deviceID, err := randomDeviceID()
	if err != nil {
		return nil, fmt.Errorf("generate device id: %w", err)
	}

	tokens, err := p.masReg.RegisterAndAuthorizeDevice(ctx, localpart, password, deviceID, p.backendPublicURL)
	if err != nil {
		return nil, fmt.Errorf("MAS public registration and OAuth device authorization: %w", err)
	}
	if tokens.UserID != mxid {
		return nil, fmt.Errorf("OAuth token returned unexpected user_id %q, want %q", tokens.UserID, mxid)
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
