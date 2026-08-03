# Plan service boundary

`internal/steward` is the public, browser-facing owner of `/plan`. It owns MAS OIDC,
browser sessions, origin/CSRF protection, rendering, and the user-facing team/seat actions.

It must not receive Dodo credentials, Dodo webhook secrets, Synapse-admin credentials, or a
billing database URL.  It calls the private Cashier only through `CashierClient`.

## Intended private protocol

Cashier exposes an internal-only versioned API corresponding exactly to `CashierClient`:

- `GET /internal/v1/plan-state`
- `POST /internal/v1/teams`
- `POST /internal/v1/team/seats`
- `DELETE /internal/v1/team/seats/{mxid}`
- `POST /internal/v1/team/checkout`
- `POST /internal/v1/team/portal`
- `POST /internal/v1/team/seat-count`
- `POST /internal/v1/team/seat-count/reconcile`

Plan will sign a short-lived EdDSA compact JWS with exactly `sub`, `aud`, `exp`, `method`, `path`,
`request_id`, and `body_sha256` claims. `body_sha256` is the raw URL-safe-base64 SHA-256 of the
exact request bytes; Plan must therefore serialize once, sign those bytes, and send those same
bytes. Commands additionally send `X-TeleCrypt-Request-ID` equal to `request_id`; plan-state uses
a generated request identifier but needs no header. Cashier verifies the assertion, uses its own
team ownership lookup, and persists idempotency for money-affecting commands. The endpoint is
reachable only on the private Plan-to-Cashier Compose network; Caddy publishes only Cashier's
signed Dodo webhook endpoint.

The package now owns the public browser flow, MAS OIDC, session cookies, exact-origin protection,
and rendering. It remains un-deployed until a coordinated exact-version release supplies the
signed Cashier transport and switches Caddy from legacy `cashier` to `plan`. A nil/unavailable
Cashier client fails closed for authenticated billing views and commands; it never falls back to
direct Dodo, Synapse, or database access.
