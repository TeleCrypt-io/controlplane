# tier_controller

`tier_controller` is a pure-Python Synapse module owned and released by the control plane. Each
Controlplane release publishes the matching, versioned
`telecrypt_tier_controller-<release>-py3-none-any.whl` and its `.sha256` file as GitHub Release
assets. The standalone `telecrypt-synapse` image builder installs that exact wheel; server
deployment configuration only selects the resulting exact image release and loads
`tier_controller.TierController`.

Controlplane does not build or publish a Synapse-module container image. Compatibility is verified
in GitHub Actions against the exact Synapse version, while `telecrypt-synapse` installs the released
wheel into its own exact derived Synapse image.

## Model

A user is **RESTRICTED** unless Synapse `users.user_type` is exactly `verified`. Missing, legacy,
and lookup-failure values are restricted. Verified users are uncapped; restricted users may not
upload media or enable room encryption and may create only `restricted_room_cap` rooms.

The module uses `module_api` callbacks only and has no credentials or outbound HTTP. User type is
read from Synapse's local database for every restricted capability decision so billing grants and
revocations take effect immediately. Room counts are queried only when a restricted user creates a
room.

## Denial behavior

Restricted uploads are rejected through Synapse's boolean media callback. Synapse 1.159.0 supplies
the client-facing upload error itself, so that path cannot include the verification guidance.
Restricted room creation and encryption-event callbacks return `Codes.FORBIDDEN` with the guidance
from the module; Synapse exposes it to clients as the error message. Encrypted `initial_state` in a
`/createRoom` request is rejected directly by the room-creation callback because Synapse does not
pass those initial state events through the event spam-checker callback.

## Server configuration

```yaml
modules:
  - module: tier_controller.TierController
    config:
      restricted_room_cap: 3
```

`user_types.extra_user_types` must include `verified` in the Synapse configuration.

## Tests

The GitHub workflow builds the wheel, installs it with Synapse `1.159.0` into a clean virtual
environment, and runs the fake-`module_api` unit suite. A tag build fails unless the wheel version
exactly equals the Controlplane release tag, then publishes the wheel and checksum together on that
GitHub Release.
