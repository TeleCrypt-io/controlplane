# TeleCrypt.io Controlplane

Public source for the non-payment control-plane components of a TeleCrypt Matrix deployment:

- `redpill` provisions Matrix agent accounts without holding a database connection.
- `janitor` locks stale accounts and sends owner digests. It reads Cashier-owned billing grants but cannot modify them.
- `steward` is the browser-facing account and team UI at the stable `/plan` URL. It uses MAS OIDC and a narrow signed private Cashier API.
- `synapse/tier_controller` is the fail-closed Synapse capability-policy module.

Cashier, Dodo integration, subscription records, payment-provider credentials, and database migrations for billing are private to the `cashier` repository. This public image contains no Cashier binary or payment-provider SDK.

## Release contract

Every release is an immutable exact tag. GitHub Actions tests the source and, only for a new tag, builds and publishes:

- `ghcr.io/telecrypt-io/telecrypt-controlplane:<release>`
- `telecrypt_tier_controller-<release>-py3-none-any.whl` and its checksum as GitHub Release assets.

The tier-controller wheel version must equal the Controlplane release tag. The standalone `telecrypt-synapse` repository consumes that exact wheel to build its own exact Synapse image. Deployment configuration, credentials, operating procedures, and production acceptance material remain private in Harness.

## Browser service boundary

Steward keeps the historic public URL `/plan` for compatibility. It owns MAS PKCE/OIDC, browser cookies, Origin protection, local MXID validation, and the team UI. It has no Dodo, Synapse-admin, or Postgres credentials. Commands are signed to the private Cashier service, which alone handles checkout, payment webhooks, entitlement mutation, and Dodo customer portal links.

`BILLING_ENV` is explicit. A test configuration visibly renders `TEST / SANDBOX — no real charges` on every Steward page. Payment card data is entered only on the Dodo-hosted checkout or customer-portal page, never at TeleCrypt.

## Development

Requires Go `1.26.4`.

```sh
go test ./...
go vet ./...
```

Run database-backed tests only against an isolated disposable database. Do not commit credentials, database URLs, signing keys, payment-provider keys, or live account data.

## License

Copyright © 2026 TeleCrypt.io. This work is licensed under the Business Source License 1.1; see [LICENSE](LICENSE).
