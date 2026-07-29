# tier_controller

`tier_controller` is a pure-Python Synapse module owned and released by the control plane. It is
baked read-only into `ghcr.io/telecrypt-io/telecrypt-synapse-tier-controller:<release>` at
`/modules/tier_controller`; server deployment configuration only selects that exact release and
loads `tier_controller.TierController`.

The image is built against `ghcr.io/dotwee/matrix-synapse-s3:v1.155.0`. Upgrade that base only as
part of a new controlplane release after the module tests and a deployment canary pass.

## Model

A user is **RESTRICTED** unless Synapse `users.user_type` is exactly `verified`. Missing, legacy,
and lookup-failure values are restricted. Verified users are uncapped; restricted users may not
upload media or enable room encryption and may create only `restricted_room_cap` rooms.

The module uses `module_api` callbacks only and has no credentials or outbound HTTP. User-type and
room-count lookups are cached for 30 seconds; an entitlement change can therefore take up to that
long to apply.

## Denial behavior

Restricted uploads are rejected through Synapse's boolean media callback. Synapse 1.155.0 supplies
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

The GitHub workflow builds the module image and runs the fake-`module_api` unit suite from the
baked image. This ensures the exact file layout and `PYTHONPATH` used at runtime are tested.
