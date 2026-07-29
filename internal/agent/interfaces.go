package agent

import (
	"context"

	"github.com/TeleCrypt-io/controlplane/internal/synapse"
)

// masRegClient is the subset of *masreg.Client that Provisioner needs. Defined here (not in
// package masreg) so tests can supply a fake without driving a real MAS instance's HTML forms.
type masRegClient interface {
	Register(ctx context.Context, username, password string) error
}

// synapseClient is the subset of *synapse.Client that Provisioner needs.
type synapseClient interface {
	CompatLogin(ctx context.Context, username, password, deviceID string) (*synapse.LoginResult, error)
}
