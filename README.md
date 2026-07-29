# TeleCrypt.io control plane

This repository contains the Go services used by a TeleCrypt-compatible
Matrix deployment:

- `redpill` provides credential-less Matrix-agent registration.
- `janitor` performs scheduled account-maintenance work.
- `cashier` provides entitlement and billing integration.
- `synapse/tier_controller` is the fail-closed Synapse capability-policy module.

The services are designed to run behind a reverse proxy and alongside Matrix
services. Deployment topology, credentials, billing configuration, operating
procedures, and production test material are deliberately not published here.

## Build and test

Requires Go `1.26.4`.

```sh
go build ./...
go vet ./...
go test ./...
```

The Dockerfile's default `controlplane` target builds the three binaries into one image. Its
`synapse-tier-controller` target builds a separate Synapse image that contains the policy module.
Both are published under the same exact release tag:

- `ghcr.io/telecrypt-io/telecrypt-controlplane:<release>`
- `ghcr.io/telecrypt-io/telecrypt-synapse-tier-controller:<release>`

The module image is based on `ghcr.io/dotwee/matrix-synapse-s3:v1.155.0`; a Synapse upgrade must
be made here, tested, and released before a server configuration may reference it. Deployments
must use exact tags and must not install the module at runtime. Pass configuration through the
environment; do not commit credentials, database URLs, signing keys, payment-provider keys, or
live account data.

## Public endpoint

When enabled by the deploying operator, `redpill` exposes:

- `POST /redpill` to provision an agent account.
- `GET /health` for a liveness check.

The request and response schema is defined by the handler and its tests in
`internal/redpillhttp`. Administrative and billing routes are deployment
specific and must not be exposed without appropriate authentication and
network controls.

## Team and seat billing

Human and bot registration remains free through MAS and `redpill`. `cashier` embeds in MAS's Plan
tab and lets a signed-in human create one team, start Dodo-hosted checkout, attach or remove local
Matrix accounts as seats, change the existing paid-seat quantity, and open Dodo's customer portal.
An attached account may be a bot or a human; the model deliberately makes no distinction.

Cashier enforces `attached seats <= paid seats` transactionally. Increasing quantity changes the
current Dodo subscription. Reducing quantity is rejected until the team owner removes enough seats;
cashier never chooses a bot to detach automatically. Removing a seat or receiving a terminal
subscription webhook immediately revokes only cashier-managed entitlement, preserving independent
manual/operator grants.

Checkout and seat-count changes reserve a durable provider idempotency key before the network call.
Known provider rejections release that reservation; timeouts and 5xx responses retain it so the
same browser action safely recovers the same request. If a seat-count webhook is missed, the Plan
page exposes an authenticated reconciliation action that reads the current Dodo subscription and
applies only the exact reserved product and quantity.

`TELECRYPT_ENV=test|production` is mandatory and must agree with the configured Dodo API origin,
Matrix server name, Homeserver, public Plan hostname, and database identifier. A test deployment
must use identifiers containing `test`, `sandbox`, or `staging`; production rejects those markers.
This is deliberately fail-closed so test Dodo state cannot share production Matrix accounts,
billing storage, or a production-looking browser origin. The test Plan page displays an unmistakable
sandbox banner and Dodo's published test-card instructions; production never renders them. Card
details are entered only on Dodo-hosted checkout or customer-portal pages and never pass through
TeleCrypt.

`MATRIX_DEPLOYMENT_ID` is also required (`billing-test` in the isolated sandbox, `production` in the
production-shaped stack). Cashier accepts only the Compose-local `http://synapse:8008` and
`http://mas:8080` enforcement targets; Compose project/network isolation binds those names to the
declared Matrix deployment.

## Development notes

Run database-backed tests only against an isolated disposable database. The
project does not provide development secrets or a production configuration.

Please report security issues privately; see [SECURITY.md](SECURITY.md).

## License

Copyright © 2026 TeleCrypt.io. This work is licensed under the Business
Source License 1.1; see [LICENSE](LICENSE).
