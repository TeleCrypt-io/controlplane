# TeleCrypt.io control plane

This repository contains the Go services used by a TeleCrypt-compatible
Matrix deployment:

- `redpill` provides credential-less Matrix-agent registration.
- `janitor` performs scheduled account-maintenance work.
- `cashier` provides entitlement and billing integration.

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

The repository's Dockerfile builds the three binaries into a single image.
Pass configuration through the environment; do not commit credentials,
database URLs, signing keys, payment-provider keys, or live account data.

## Public endpoint

When enabled by the deploying operator, `redpill` exposes:

- `POST /redpill` to provision an agent account.
- `GET /health` for a liveness check.

The request and response schema is defined by the handler and its tests in
`internal/redpillhttp`. Administrative and billing routes are deployment
specific and must not be exposed without appropriate authentication and
network controls.

## Development notes

Run database-backed tests only against an isolated disposable database. The
project does not provide development secrets or a production configuration.

Please report security issues privately; see [SECURITY.md](SECURITY.md).

## License

Copyright © 2026 TeleCrypt.io. This work is licensed under the Business
Source License 1.1; see [LICENSE](LICENSE).
