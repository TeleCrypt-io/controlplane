package agent

import (
	"context"

	"github.com/TeleCrypt-io/controlplane/internal/masreg"
)

// masRegClient is the subset of *masreg.Client that Provisioner needs. Defined here (not in
// package masreg) so tests can supply a fake without driving a real MAS instance's HTML forms.
type masRegClient interface {
	RegisterAndAuthorizeDevice(ctx context.Context, username, password, deviceID, clientURI string) (*masreg.DeviceTokens, error)
}
