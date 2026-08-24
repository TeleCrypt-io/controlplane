# tier_controller

`tier_controller` is a pure-Python Synapse module. The Controlplane release workflow publishes an
exactly versioned `telecrypt_tier_controller-<release>-py3-none-any.whl` and one canonical
`controlplane-<release>.digest.json` binding asset as GitHub Release assets. The standalone
`telecrypt-synapse` repository must update its pinned manifest to that exact coordinate before its
image builder can use a new wheel; this repository does not change that manifest. Server deployment
configuration selects the resulting exact image release and loads `tier_controller.TierController`.

Controlplane does not build or publish a Synapse-module container image. Compatibility is verified
in GitHub Actions by installing the wheel without dependencies into the official exact
`ghcr.io/element-hq/synapse:v1.159.0` runtime. After its manifest is updated, the separate
`telecrypt-synapse` repository can install the released wheel into its own exact derived Synapse
image.

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

The GitHub workflow installs its build tooling from the hash-locked `requirements-test.txt`, then
installs the wheel without dependencies into the exact Synapse `1.159.0` runtime and runs the
stdlib fake-`module_api` unit suite. A tag build fails unless the wheel version exactly equals the
Controlplane release tag, then publishes the wheel and digest binding together on that GitHub
Release.
