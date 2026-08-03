# Plan service boundary

`internal/plan` is the public, browser-facing owner of `/plan`.  It will own MAS OIDC,
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

Plan will sign a short-lived assertion containing the authenticated MAS MXID, intended Cashier
audience, expiry, request method/path, and request identifier. Cashier verifies that assertion,
uses its own team ownership lookup, and persists idempotency for money-affecting commands. The
endpoint is reachable only on the private Plan-to-Cashier Compose network; Caddy publishes only
Cashier's signed Dodo webhook endpoint.

This package is intentionally fail-closed until the OIDC/session code and Cashier transport move
in a coordinated, exact-version release. The legacy `cashier` remains the deployed `/plan` owner.
