# TeleCrypt.io Controlplane

Public source for the non-payment control-plane components of a TeleCrypt Matrix deployment:

- `redpill` provisions Matrix agent accounts without holding a database connection.
- `janitor` locks stale accounts and sends owner digests. It reads Cashier-owned billing grants but cannot modify them.
- `steward` is the browser-facing account and plan-management UI at the stable `/plan` URL. It uses MAS OIDC and a narrow signed private Cashier API.
- `synapse/tier_controller` is the fail-closed Synapse capability-policy module.

Cashier, Dodo integration, subscription records, payment-provider credentials, and database migrations for billing are private to the `cashier` repository. This public image contains no Cashier binary or payment-provider SDK.

## Release contract

Every source version is an immutable exact tag. GitHub Actions tests the source and, only for a new
tag, publishes two distinct artifact types:

- The Go services are released only as `ghcr.io/telecrypt-io/controlplane:<release>`. The image
  contains Redpill, Janitor, and Steward; no executable archives are attached to GitHub Releases.
- The GitHub Release, titled `tier-controller <release>`, contains only
  `telecrypt_tier_controller-<release>-py3-none-any.whl` and its checksum. This is the public
  distribution channel for the Synapse module.

The wheel version must equal the source/image tag. The standalone `telecrypt-synapse` repository
consumes that exact wheel to build its own exact Synapse image. The shared tag is the exact
cross-repository release coordinate, not a claim that the GitHub Release distributes the Go
services. Deployment
configuration, credentials, operating procedures, and production acceptance material remain
private in Harness.

## Repository layout

- `cmd/` contains the minimal `main` packages for the three independently deployed processes:
  Redpill, Janitor, and Steward.
- `internal/` contains their shared Go implementation. Go deliberately prevents packages below
  `internal/` from being imported by unrelated repositories.
- `synapse/tier_controller/` contains the public Python package released as the exact wheel for
  `telecrypt-synapse`; it is not copied into the Controlplane container image.

## Browser service boundary

Steward owns the public `/plan` URL, MAS PKCE/OIDC, browser cookies, Origin protection, local MXID
validation, and the plan UI. It has no Dodo, Synapse-admin, or Postgres credentials. Commands are
signed to the private Cashier service, which alone handles checkout, payment webhooks, entitlement
mutation, and Dodo customer portal links.

`BILLING_ENV` is explicit. A test configuration visibly renders `TEST / SANDBOX — no real charges` on every Steward page. Payment card data is entered only on the Dodo-hosted checkout or customer-portal page, never at TeleCrypt.

Janitor runs one sweep per invocation and reads Cashier-owned billing grants through
`JANITOR_DB_URL`, using a separate database credential from Cashier's `CASHIER_DB_URL`. The
Janitor role is read-only on the private `cashier` schema and may write only its own `locker_state`
maintenance table.

## Redpill credential contract

`POST /redpill` is the public, rate-limited component for creating an agent account. It
uses only MAS's public password-registration forms, dynamic registration of a public native OAuth
client (`token_endpoint_auth_method: none`), and MAS's device-authorization pages through the
new account's short-lived cookie session. It never receives a MAS/Synapse admin credential, a
personal access token, or a static OAuth client secret, and it never uses Matrix
`m.login.password`.

The one response contains the MXID, generated MAS password, access/refresh tokens, expiry,
device ID, homeserver, and `issuer`/`client_id`/`token_endpoint` needed to refresh directly with
MAS. The password is a recovery credential; agents should use the refresh token. Redpill stores
none of those values, logs no credential-exchange details, and sends `Cache-Control: no-store`.
The fixed in-process limiter allows 5 requests per source and 60 total requests per 60 seconds.
Trusted client-IP extraction remains enforced at the Redpill boundary.

## Development

Requires Go `1.26.4`.

```sh
go test ./...
go vet ./...
```

Run database-backed tests only against an isolated disposable database. Do not commit credentials, database URLs, signing keys, payment-provider keys, or live account data.

The opt-in MAS integration test creates a throwaway account, OAuth client, and device. Run it
only against an isolated disposable MAS/Synapse stack on the local machine. The test accepts only
HTTP loopback URLs on the same origin, with MAS mounted at `/auth` and the Matrix origin at `/`.
The explicit confirmation variable is required so the test cannot be enabled by accident:

```sh
MASREG_INTEGRATION_DISPOSABLE=YES \
MASREG_INTEGRATION_MAS_BASE_URL=http://127.0.0.1:8008/auth \
MASREG_INTEGRATION_MATRIX_ORIGIN=http://127.0.0.1:8008 \
go test -tags=integration ./internal/masreg -run '^TestRegisterAndAuthorizeDeviceDisposableMAS$' -count=1
```

Never point these variables at production or a shared test environment. The generated account,
client, device, password, and tokens are disposable test data and must not be retained.

## License

Copyright © 2026 TeleCrypt.io. This work is licensed under the Business Source License 1.1; see [LICENSE](LICENSE).
