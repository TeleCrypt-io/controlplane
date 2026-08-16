// Package steward owns TeleCrypt's public Plan surface. It deliberately has no
// Dodo, Synapse-admin, or billing-database dependency: it authenticates a browser with MAS and
// invokes the private Cashier service through this narrow interface.
package steward

import (
	"context"
	"time"
)

// Principal is the authenticated Matrix identity established by Plan's MAS OIDC session.
// Cashier must treat it as an assertion to verify, not as a client-supplied authorization
// decision. HTTPCashierClient carries it in a short-lived, audience-bound, signed assertion.
type Principal struct {
	MXID string
}

// Plan is the billing-safe subset of a user's plan shown to its administrator. Provider
// identifiers and billing credentials are intentionally never returned to the browser-facing
// Plan service.
type Plan struct {
	ID                 string `json:"id"`
	SubscriptionStatus string `json:"subscription_status"`
	PaidSeats          int    `json:"paid_seats"`
	PendingPaidSeats   *int   `json:"pending_paid_seats"`
	CheckoutActive     bool   `json:"checkout_active"`
	HasBillingAccount  bool   `json:"has_billing_account"`
}

// Seat is a Matrix account attached to a plan.
type Seat struct {
	MXID      string    `json:"mxid"`
	CreatedAt time.Time `json:"created_at"`
}

// PlanState is all information the Plan renderer needs for one authenticated principal.
type PlanState struct {
	Plan  *Plan  `json:"plan"`
	Seats []Seat `json:"seats"`
}

// CashierClient is the complete public-Plan-to-private-Cashier contract. It intentionally
// omits provider webhooks, arbitrary subscription lookup, Synapse administration, and direct
// database access. Every command is performed for principal; Cashier must derive ownership from
// that identity rather than accepting an administrator MXID or plan ID supplied by a browser.
//
// Implementations must use short-lived, audience-bound Plan assertions on a private Compose
// network. Monetary commands must accept and durably honour requestID for safe browser retries.
type CashierClient interface {
	PlanState(ctx context.Context, principal Principal) (PlanState, error)
	CreatePlan(ctx context.Context, principal Principal, requestID string) (Plan, error)
	AttachSeat(ctx context.Context, principal Principal, requestID, mxid string) error
	RemoveSeat(ctx context.Context, principal Principal, requestID, mxid string) error
	StartCheckout(ctx context.Context, principal Principal, requestID string, quantity int) (paymentLink string, err error)
	OpenCustomerPortal(ctx context.Context, principal Principal, requestID string) (portalLink string, err error)
	ChangeSeatCount(ctx context.Context, principal Principal, requestID string, quantity int) error
	ReconcileSeatCount(ctx context.Context, principal Principal, requestID string) error
}
