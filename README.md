# TeleCrypt.io Controlplane

Public source for the non-payment control-plane components of a TeleCrypt Matrix deployment:

- `redpill` rate-limits public agent requests and signs a narrow command to the private issuer. It
  holds no MAS credential and never handles a password.
- `agentissuer` is the private passwordless provisioning authority. It alone holds a dedicated MAS
  OAuth client credential, creates a fresh MAS user, and issues a revocable bot personal session.
- `janitor` locks stale accounts and sends owner digests. It reads Cashier-owned billing grants but cannot modify them.
- `steward` is the browser-facing account and team UI at the stable `/plan` URL. It uses MAS OIDC and a narrow signed private Cashier API.
- `synapse/tier_controller` is the fail-closed Synapse capability-policy module.

Cashier, Dodo integration, subscription records, payment-provider credentials, and database migrations for billing are private to the `cashier` repository. This public image contains no Cashier binary or payment-provider SDK.

## Release contract

Every source version is an immutable exact tag. GitHub Actions tests the source and, only for a new
tag, publishes two distinct artifact types:

- The Go services are released only as `ghcr.io/telecrypt-io/controlplane:<release>`. The image
  contains Redpill, Agent Issuer, Janitor, and Steward; no executable archives are attached to
  GitHub Releases.
- The GitHub Release, titled `tier-controller <release>`, contains only
  `telecrypt_tier_controller-<release>-py3-none-any.whl` and its checksum. This is the public
  distribution channel for the Synapse module.

The wheel version must equal the source/image tag. The standalone `telecrypt-synapse` repository
consumes that exact wheel to build its own exact Synapse image. The shared tag is a compatibility
coordinate, not a claim that the GitHub Release distributes the Go services. Deployment
configuration, credentials, operating procedures, and production acceptance material remain
private in Harness.

## Repository layout

- `cmd/` contains the minimal `main` packages for the four independently deployed processes:
  Redpill, Agent Issuer, Janitor, and Steward.
- `internal/` contains their shared Go implementation. Go deliberately prevents packages below
  `internal/` from being imported by unrelated repositories.
- `synapse/tier_controller/` contains the public Python package released as the exact wheel for
  `telecrypt-synapse`; it is not copied into the Controlplane container image.

## Browser service boundary

Steward keeps the historic public URL `/plan` for compatibility. It owns MAS PKCE/OIDC, browser cookies, Origin protection, local MXID validation, and the team UI. It has no Dodo, Synapse-admin, or Postgres credentials. Commands are signed to the private Cashier service, which alone handles checkout, payment webhooks, entitlement mutation, and Dodo customer portal links.

`BILLING_ENV` is explicit. A test configuration visibly renders `TEST / SANDBOX — no real charges` on every Steward page. Payment card data is entered only on the Dodo-hosted checkout or customer-portal page, never at TeleCrypt.

## Agent provisioning boundary

Redpill never collects or generates a password and never calls Matrix compatibility login. Its
only authority is an Ed25519 key that signs the fixed private `POST /internal/v1/agents` command.
Agent Issuer verifies the request-bound signature and rejects reused request IDs, then obtains a short-lived `urn:mas:admin` token via
OAuth client credentials, creates a passwordless MAS account, and issues a personal access token
with only Matrix client and generated-device scopes. If token issuance fails after account
creation, it deactivates the incomplete account.

MAS currently supports bot personal access tokens but no self-service renewal protocol. Issued
agent tokens therefore remain non-expiring and administratively revocable. That lifecycle is an
explicit risk decision; do not silently add expiry until Redpill has a tested rotation flow.

## Development

Requires Go `1.26.4`.

```sh
go test ./...
go vet ./...
```

Run database-backed tests only against an isolated disposable database. Do not commit credentials, database URLs, signing keys, payment-provider keys, or live account data.

## License

Copyright © 2026 TeleCrypt.io. This work is licensed under the Business Source License 1.1; see [LICENSE](LICENSE).
