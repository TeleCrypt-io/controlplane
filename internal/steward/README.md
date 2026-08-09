# Steward service boundary

`internal/steward` is the deployed public, browser-facing owner of `/plan`. It owns MAS OIDC,
browser sessions, origin/CSRF protection, rendering, and the user-facing team, seat, checkout,
and billing-portal actions. MAS embeds this stable URL in its account-management iframe through
`plan_management_iframe_uri`; it also works as a standalone page.

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

Steward signs a short-lived EdDSA compact JWS with exactly `sub`, `aud`, `exp`, `method`, `path`,
`request_id`, and `body_sha256` claims. `body_sha256` is the raw URL-safe-base64 SHA-256 of the
exact request bytes; Steward serializes once, signs those bytes, and sends those same bytes.
Commands additionally send `X-TeleCrypt-Request-ID` equal to `request_id`; plan-state uses a
generated request identifier but needs no header. Cashier verifies the assertion, uses its own
team ownership lookup, and persists idempotency for money-affecting commands. The endpoint is
reachable only on the private Steward-to-Cashier Compose network; Caddy publishes only Cashier's
signed Dodo webhook endpoint.

The package owns the public browser flow, MAS OIDC, session cookies, exact-origin protection, and
rendering. An unavailable Cashier client fails closed for authenticated billing views and commands;
it never falls back to direct Dodo, Synapse, or database access.

## Plan UI ownership and release integration

`assets/product.css`, `assets/plan.html`, `assets/plan.css`, and `assets/plan.js` are embedded in the
Steward binary. They need no browser-side package manager, CDN, or runtime dependency.
`product.css` is a byte-identical vendored copy of the exact framework-neutral shared UI core used
by Storage; `plan.css` contains only Plan-specific composition and responsive layout. The page thus
uses the same light canvas, white surfaces, system typography, compact controls, and neutral borders
without giving this Go service a frontend build pipeline.

The shared library remains the source of those visual tokens and component conventions. Updating
the vendored file requires an exact shared-library release plus a byte-identity check before the
Controlplane release. `assets/SHARED_UI_PROVENANCE.json` records the exact shared source commit and
content hash used by this checkout. Product assets are not inferred from service favicons: Plan embeds
TeleCrypt's original `logo-mark.png`, while Storage retains its existing end-user appearance.

Before release, integrate these files into a reviewed immutable Controlplane release, run the
Steward rendering and security tests plus an authenticated visual regression against the exact
release artifact, and record that exact release for promotion. No deployment should be made from
this working tree.
