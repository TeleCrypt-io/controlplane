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
	masReg     masRegClient
	homeserver string // e.g. https://backend.telecrypt.io
	serverName string // e.g. telecrypt.io — used to build MXIDs, decoupled from homeserver host
}

// NewProvisioner creates a Provisioner. The serverName override is optional: when non-empty it is
// used for MXID construction (allowing the homeserver endpoint and the server_name to differ);
// when empty it falls back to the host from homeserver for backward compatibility.
func NewProvisioner(m masRegClient, homeserver, serverName string) (*Provisioner, error) {
	u, err := url.Parse(homeserver)
	if err != nil {
		return nil, fmt.Errorf("parse homeserver URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("homeserver URL %q has no host", homeserver)
	}
	if serverName == "" {
		serverName = u.Host
	}
	return &Provisioner{
		masReg:     m,
		homeserver: homeserver,
		serverName: serverName,
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

	tokens, err := p.masReg.RegisterAndAuthorizeDevice(ctx, localpart, password, deviceID, p.homeserver)
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
		Homeserver:         p.homeserver,
		OAuthIssuer:        tokens.Issuer,
		OAuthClientID:      tokens.ClientID,
		OAuthTokenEndpoint: tokens.TokenEndpoint,
	}, nil
}
