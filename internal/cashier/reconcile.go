package cashier

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/TeleCrypt-io/controlplane/internal/db"
)

type synapseAdmin interface {
	SetUserTypeVerified(ctx context.Context, mxid string) error
	ClearUserType(ctx context.Context, mxid string) error
	UserExists(ctx context.Context, mxid string) (bool, error)
}

type entitlementStore interface {
	GetTeamByID(ctx context.Context, teamID uuid.UUID) (db.Team, error)
	ListSeatsForTeam(ctx context.Context, teamID uuid.UUID) ([]db.Seat, error)
	HasManualVerificationGrant(ctx context.Context, mxid string) (bool, error)
	HasBillingVerificationGrant(ctx context.Context, mxid string) (bool, error)
	InsertBillingVerificationGrant(ctx context.Context, teamID uuid.UUID, mxid string) error
	DeleteBillingVerificationGrant(ctx context.Context, mxid string) error
}

// Reconciler applies team entitlement to Synapse user_type and the billing verification grant
// table. Manual/break-glass grants are intentionally a different source: a cashier revocation
// only removes its own billing grant and clears Synapse only when no manual grant remains.
//
// Synapse is the enforcement point, so every transition is applied there before the local
// bookkeeping table is changed. This deliberately permits an idempotent Synapse request on
// a retry: if Synapse succeeds but Postgres is temporarily unavailable, the next reconcile
// repeats the safe remote operation and then repairs the local record. Reversing the order
// would make a failed Synapse call look complete to later reconciliations.
type Reconciler struct {
	store   entitlementStore
	synapse synapseAdmin
}

func NewReconciler(store entitlementStore, synapse synapseAdmin) *Reconciler {
	return &Reconciler{store: store, synapse: synapse}
}

// ReconcileTeamEntitlement is the one place seat verification happens for team billing.
// TODO: Dodo's customer portal allows seat-count changes outside our UI (no SDK knob to disable).
// When that happens, reconcile will auto-drop newest seats to enforce attached <= paid.
// Detect over-subscription here and emit a structured log alert so ops can notify the team admin.
func (r *Reconciler) ReconcileTeamEntitlement(ctx context.Context, teamID uuid.UUID) error {
	team, err := r.store.GetTeamByID(ctx, teamID)
	if err != nil {
		return err
	}

	seats, err := r.store.ListSeatsForTeam(ctx, teamID)
	if err != nil {
		return err
	}

	entitled := make(map[string]bool)
	active := team.SubscriptionStatus == "active" || team.SubscriptionStatus == "on_hold"
	if active {
		limit := team.PaidSeats
		if limit > len(seats) {
			limit = len(seats)
		}
		for i := 0; i < limit; i++ {
			entitled[seats[i].MXID] = true
		}
	}

	for _, seat := range seats {
		if err := r.reconcileSeat(ctx, teamID, seat.MXID, entitled[seat.MXID]); err != nil {
			return err
		}
	}

	// Detect over-subscription (attached seats > paid seats) — can happen if Dodo portal
	// changed quantity outside our UI. Log structured alert for ops visibility.
	if len(seats) > team.PaidSeats && active {
		slog.Warn("cashier: team over-subscribed after reconcile",
			"team_id", teamID,
			"paid_seats", team.PaidSeats,
			"attached_seats", len(seats),
			"subscription_status", team.SubscriptionStatus,
			"cause", "dodo_portal_quantity_change_or_webhook_delay",
		)
	}
	return nil
}

// ClearAllTeamSeats unverifies every seat on an inactive subscription.
func (r *Reconciler) ClearAllTeamSeats(ctx context.Context, teamID uuid.UUID) error {
	seats, err := r.store.ListSeatsForTeam(ctx, teamID)
	if err != nil {
		return err
	}
	for _, seat := range seats {
		if err := r.unverifySeat(ctx, seat.MXID); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) reconcileSeat(ctx context.Context, teamID uuid.UUID, mxid string, shouldVerify bool) error {
	if shouldVerify {
		billingGranted, err := r.store.HasBillingVerificationGrant(ctx, mxid)
		if err != nil {
			return err
		}
		if billingGranted {
			return nil
		}

		// Always write Synapse before recording the local billing grant. This is deliberately
		// safe even when a manual grant already exists: setting verified is idempotent and
		// repairs any accidental Synapse drift, while a failed DB write is retried remotely.
		if err := r.synapse.SetUserTypeVerified(ctx, mxid); err != nil {
			return fmt.Errorf("verify %s: %w", mxid, err)
		}
		if err := r.store.InsertBillingVerificationGrant(ctx, teamID, mxid); err != nil {
			return fmt.Errorf("record billing grant %s: %w", mxid, err)
		}
		slog.Info("cashier: granted billing verification", "mxid", mxid, "team_id", teamID)
		return nil
	}
	return r.unverifySeat(ctx, mxid)
}

func (r *Reconciler) unverifySeat(ctx context.Context, mxid string) error {
	billingGranted, err := r.store.HasBillingVerificationGrant(ctx, mxid)
	if err != nil {
		return err
	}
	if !billingGranted {
		return nil
	}

	manualGranted, err := r.store.HasManualVerificationGrant(ctx, mxid)
	if err != nil {
		return err
	}
	if manualGranted {
		// A manual grant keeps the effective entitlement alive, so no Synapse mutation is
		// needed. Delete only cashier's grant; if this local write fails it is harmlessly
		// retried and must never trigger a clear on the next run.
		if err := r.store.DeleteBillingVerificationGrant(ctx, mxid); err != nil {
			return fmt.Errorf("remove billing grant %s: %w", mxid, err)
		}
		slog.Info("cashier: removed billing grant; manual grant remains", "mxid", mxid)
		return nil
	}

	// No other source keeps the user verified. As on grant, mutate Synapse before local state:
	// a failed clear leaves the billing grant present and therefore guarantees a later retry.
	if err := r.synapse.ClearUserType(ctx, mxid); err != nil {
		return fmt.Errorf("unverify %s: %w", mxid, err)
	}
	if err := r.store.DeleteBillingVerificationGrant(ctx, mxid); err != nil {
		return fmt.Errorf("remove billing grant %s: %w", mxid, err)
	}
	slog.Info("cashier: removed billing verification", "mxid", mxid)
	return nil
}

// RevokeSeat removes a deleted seat's cashier-managed entitlement before its seat row is
// removed. Once the row is gone it is no longer part of a team's reconciliation input, so this
// explicit transition is required to avoid leaving it verified forever.
func (r *Reconciler) RevokeSeat(ctx context.Context, mxid string) error {
	return r.unverifySeat(ctx, mxid)
}
