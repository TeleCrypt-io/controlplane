# Controlplane internal packages

`internal/` contains implementation shared by the Controlplane executables. Go prevents an
unrelated repository from importing these packages. The public entry points are deliberately
small `main` packages in `cmd/`:

- `cmd/redpill` serves `POST /redpill` and provisions a newly registered user's Matrix agent.
- `cmd/janitor` is a scheduled, non-listening maintenance process.
- `cmd/steward` serves the authenticated account, team, and subscription UI at `/plan`.

## Package responsibilities

| Package | Responsibility | Deliberate boundary |
| --- | --- | --- |
| `agent` | Coordinates Matrix-agent provisioning after a user registers. | No database or MAS-admin credential. |
| `config` | Loads and validates the narrowly scoped configuration of each executable. | Rejects incomplete or inconsistent runtime configuration. |
| `db` | Janitor's small maintenance-state schema and read-side billing-grant access. | Does not create payments, subscriptions, or provider records. |
| `janitor` | Finds stale unclaimed accounts, locks them through MAS, and sends the owner digest. | No HTTP listener. |
| `masadmin` | MAS admin OAuth client used only by Janitor. | Never used by Redpill or Steward. |
| `masreg` | MAS public registration, dynamic-client, and device-OAuth client used by Redpill. | Does not use MAS-admin authority or a client secret. |
| `redpillhttp` | Redpill request parsing, client-IP handling, response shaping, and rate limiting. | Public surface is limited to the registration endpoint. |
| `steward` | MAS OIDC, browser sessions, CSRF/origin checks, rendering, and signed Cashier commands. | Has no Dodo, Synapse-admin, or Postgres credential. |

## Billing and team-management flow

`Steward` is the user-facing team-management component. A user authenticates with MAS, then
Steward reads team state or requests a change through the private Cashier interface. The request
is signed and bound to its method, path, exact body, and a short expiry. Cashier is the sole
holder of payment-provider credentials and billing-write authority; it performs payment actions
and applies the resulting entitlement to Synapse.

```text
MAS account page -> /plan (Steward) -> signed private Cashier request -> billing / entitlement
```

The Synapse `tier_controller` is intentionally not under `internal/`: it runs inside the external
Synapse process and is released as the separately installable `telecrypt-tier-controller` wheel.
