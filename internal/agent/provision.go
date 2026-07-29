// Package agent implements redpill's agent-provisioning logic: generate a localpart and
// password, register the account through MAS's public registration form (internal/masreg, no
// admin credentials involved), log in via Synapse compat login to mint a non-expiring token, and
// discard the password. This replaces the old admin-API-driven flow now that morpheus (and the
// standing MAS/Synapse admin credentials it held) no longer exists.
package agent

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/synapse"
)

const (
	compatLoginMaxAttempts  = 6
	compatLoginInitialDelay = 100 * time.Millisecond
)

type Provisioned struct {
	MXID        string
	AccessToken string
	DeviceID    string
	Homeserver  string
}

type Provisioner struct {
	masReg     masRegClient
	synapse    synapseClient
	homeserver string // e.g. https://backend.telecrypt.io
	serverName string // e.g. telecrypt.io — used to build MXIDs, decoupled from homeserver host
}

// NewProvisioner creates a Provisioner. The serverName override is optional: when non-empty it is
// used for MXID construction (allowing the homeserver endpoint and the server_name to differ);
// when empty it falls back to the host from homeserver for backward compatibility.
func NewProvisioner(m masRegClient, sy synapseClient, homeserver, serverName string) (*Provisioner, error) {
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
		synapse:    sy,
		homeserver: homeserver,
		serverName: serverName,
	}, nil
}

// ProvisionAgent generates a random localpart and password, registers the account through MAS's
// public registration form, logs in via Synapse compat login to mint a non-expiring token, and
// discards the password — it is never logged or returned.
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

	if err := p.masReg.Register(ctx, localpart, password); err != nil {
		return nil, fmt.Errorf("mas register: %w", err)
	}

	deviceID, err := randomDeviceID()
	if err != nil {
		return nil, fmt.Errorf("generate device id: %w", err)
	}

	// password is used here and nowhere else: never logged, never stored, never part of the
	// response below.
	login, err := p.compatLoginAfterRegistration(ctx, localpart, password, deviceID)
	if err != nil {
		return nil, fmt.Errorf("compat login: %w", err)
	}
	if login.UserID != mxid {
		return nil, fmt.Errorf("compat login returned unexpected user_id %q, want %q", login.UserID, mxid)
	}

	return &Provisioned{
		MXID:        mxid,
		AccessToken: login.AccessToken,
		DeviceID:    deviceID,
		Homeserver:  p.homeserver,
	}, nil
}

// compatLoginAfterRegistration tolerates the short window in which MAS has accepted a
// registration but its asynchronous provisioning job has not yet made the user visible to
// Synapse. The password and device ID remain unchanged, and only transport/5xx failures retry.
func (p *Provisioner) compatLoginAfterRegistration(
	ctx context.Context,
	localpart, password, deviceID string,
) (*synapse.LoginResult, error) {
	delay := compatLoginInitialDelay
	for attempt := 1; ; attempt++ {
		login, err := p.synapse.CompatLogin(ctx, localpart, password, deviceID)
		if err == nil {
			return login, nil
		}
		if attempt >= compatLoginMaxAttempts || !synapse.IsRetryableCompatLogin(err) {
			return nil, err
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		delay *= 2
	}
}
