package cashier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	dodo "github.com/dodopayments/dodopayments-go"
	"github.com/dodopayments/dodopayments-go/option"
	"github.com/dodopayments/dodopayments-go/shared"
	"github.com/google/uuid"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/masoidc"
)

type teamStore interface {
	CreateTeam(ctx context.Context, adminMXID string) (db.Team, error)
	GetTeamByAdminMXID(ctx context.Context, adminMXID string) (db.Team, bool, error)
	GetTeamByID(ctx context.Context, teamID uuid.UUID) (db.Team, error)
	GetSubscriptionBinding(ctx context.Context, subscriptionID string) (db.SubscriptionBinding, bool, error)
	AttachSeat(ctx context.Context, teamID uuid.UUID, mxid string) error
	DeleteSeat(ctx context.Context, mxid string) error
	CountSeatsForTeam(ctx context.Context, teamID uuid.UUID) (int, error)
	ListSeatsForTeam(ctx context.Context, teamID uuid.UUID) ([]db.Seat, error)
	UpdateTeamSubscription(ctx context.Context, teamID uuid.UUID, status string, paidSeats int, dodoCustomerID, dodoSubscriptionID *string) error
	BeginCheckout(ctx context.Context, teamID uuid.UUID, quantity int, now time.Time) (db.CheckoutReservation, error)
	CompleteCheckoutReservation(ctx context.Context, teamID uuid.UUID, attemptID uuid.UUID, sessionID string) error
	ReleaseCheckoutReservation(ctx context.Context, teamID uuid.UUID, attemptID uuid.UUID) error
	ReserveSeatCountChange(ctx context.Context, teamID uuid.UUID, quantity int, now time.Time) (db.SeatCountReservation, error)
	ReleaseSeatCountChange(ctx context.Context, teamID uuid.UUID, attemptID uuid.UUID) error
	BindCurrentSubscription(ctx context.Context, teamID uuid.UUID, subscriptionID, customerID, status string, paidSeats int) error
	IsWebhookProcessed(ctx context.Context, webhookID string) (bool, error)
	MarkWebhookProcessed(ctx context.Context, webhookID string) error
}

type Server struct {
	cfg        *config.CashierConfig
	store      teamStore
	reconciler *Reconciler
	oidc       *masoidc.Client
	session    *Session
	dodo       *dodo.Client
	mux        *http.ServeMux
}

func NewServer(cfg *config.CashierConfig, store teamStore, reconciler *Reconciler, oidc *masoidc.Client, session *Session, dodoClient *dodo.Client) *Server {
	s := &Server{
		cfg:        cfg,
		store:      store,
		reconciler: reconciler,
		oidc:       oidc,
		session:    session,
		dodo:       dodoClient,
		mux:        http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /plan", s.handlePlan)
	s.mux.HandleFunc("GET /plan/login", s.handleLogin)
	s.mux.HandleFunc("GET /plan/callback", s.handleCallback)
	s.mux.Handle("POST /api/team", s.requireBrowserSession(http.HandlerFunc(s.handleCreateTeam)))
	s.mux.Handle("POST /api/team/seats", s.requireBrowserSession(http.HandlerFunc(s.handleAddSeat)))
	s.mux.Handle("DELETE /api/team/seats/{mxid}", s.requireBrowserSession(http.HandlerFunc(s.handleDeleteSeat)))
	s.mux.Handle("POST /api/team/checkout", s.requireBrowserSession(http.HandlerFunc(s.handleCheckout)))
	s.mux.Handle("POST /api/team/portal", s.requireBrowserSession(http.HandlerFunc(s.handlePortal)))
	s.mux.Handle("POST /api/team/seat-count", s.requireBrowserSession(http.HandlerFunc(s.handleChangeSeatCount)))
	s.mux.Handle("POST /api/team/seat-count/reconcile", s.requireBrowserSession(http.HandlerFunc(s.handleReconcileSeatCount)))
	// Keep the old endpoint temporarily so a cached Plan iframe cannot bypass the new guards.
	s.mux.Handle("POST /api/team/downgrade-request", s.requireBrowserSession(http.HandlerFunc(s.handleChangeSeatCount)))
	s.mux.HandleFunc("POST /webhooks/dodo", s.handleDodoWebhook)
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// requireBrowserSession protects the browser-only, state-changing Plan APIs. The session cookie
// is deliberately HttpOnly, so a synchronizer token is not practical here; instead, require the
// browser's Origin header to exactly match the public Plan origin. Cross-site form posts and
// fetches therefore fail even if a browser would otherwise attach the session cookie. Dodo's
// server-to-server webhook is registered separately and does not pass through this middleware.
func (s *Server) requireBrowserSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mxid, err := s.session.MXID(r)
		if err != nil {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		if !s.isPlanOrigin(r.Header.Get("Origin")) {
			http.Error(w, "invalid request origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withMXID(r.Context(), mxid)))
	})
}

func (s *Server) isPlanOrigin(origin string) bool {
	if origin == "" || origin == "null" || s.cfg == nil {
		return false
	}
	planURL, err := url.Parse(s.cfg.PlanPublicURL)
	if err != nil || planURL.Scheme == "" || planURL.Host == "" {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Scheme == "" || originURL.Host == "" || originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" || originURL.User != nil {
		return false
	}
	return originURL.Scheme == planURL.Scheme && originURL.Host == planURL.Host
}

func (s *Server) teamForSession(ctx context.Context) (db.Team, error) {
	mxid, ok := mxidFromCtx(ctx)
	if !ok {
		return db.Team{}, errUnauthorized
	}
	team, found, err := s.store.GetTeamByAdminMXID(ctx, mxid)
	if err != nil {
		return db.Team{}, err
	}
	if !found {
		return db.Team{}, fmt.Errorf("team not found")
	}
	return team, nil
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	mxid, err := s.session.MXID(r)
	loggedIn := err == nil

	var team *db.Team
	var seats []db.Seat
	if loggedIn {
		t, found, err := s.store.GetTeamByAdminMXID(r.Context(), mxid)
		if err != nil {
			slog.Error("cashier: load Plan team", "mxid", mxid, "error", err)
			http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if found {
			team = &t
			seats, err = s.store.ListSeatsForTeam(r.Context(), t.ID)
			if err != nil {
				slog.Error("cashier: load Plan seats", "team_id", t.ID, "error", err)
				http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}
	}

	data := struct {
		LoggedIn       bool
		TestMode       bool
		MXID           string
		RegisterURL    string
		Team           *db.Team
		Seats          []db.Seat
		CanCheckout    bool
		CheckoutActive bool
		CanChangeSeats bool
	}{
		LoggedIn:    loggedIn,
		TestMode:    s.cfg.TelecryptEnv == "test",
		MXID:        mxid,
		RegisterURL: strings.TrimRight(s.cfg.Homeserver, "/") + "/auth/register",
		Team:        team,
		Seats:       seats,
	}
	if team != nil {
		switch team.SubscriptionStatus {
		case "none", "failed", "cancelled", "expired":
			data.CanCheckout = true
		case "pending":
			data.CheckoutActive = true
		case "active", "on_hold":
			data.CanChangeSeats = true
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := planTmpl.Execute(w, data); err != nil {
		slog.Error("cashier: render plan page", "error", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier, challenge, err := masoidc.NewPKCEPair()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := uuid.NewString()
	setOAuthCookies(w, state, verifier)
	http.Redirect(w, r, s.oidc.AuthorizeURL(state, challenge), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	state, err := readOAuthCookie(r, oauthStateCookie)
	if err != nil || r.URL.Query().Get("state") != state {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	verifier, err := readOAuthCookie(r, oauthPKCECookie)
	if err != nil {
		http.Error(w, "invalid oauth session", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	token, err := s.oidc.ExchangeCode(r.Context(), code, verifier)
	if err != nil {
		slog.Error("cashier: token exchange", "error", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	username, err := s.oidc.Username(r.Context(), token)
	if err != nil {
		slog.Error("cashier: userinfo", "error", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	clearOAuthCookies(w)
	mxid := fmt.Sprintf("@%s:%s", username, s.cfg.ServerName)
	s.session.Set(w, mxid)
	http.Redirect(w, r, s.cfg.PlanPublicURL, http.StatusFound)
}

func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
	mxid, _ := mxidFromCtx(r.Context())
	if _, found, _ := s.store.GetTeamByAdminMXID(r.Context(), mxid); found {
		http.Error(w, "team already exists", http.StatusConflict)
		return
	}
	team, err := s.store.CreateTeam(r.Context(), mxid)
	if err != nil {
		slog.Error("cashier: create team", "error", err)
		http.Error(w, "create team failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"team_id": team.ID.String()})
}

type seatRequest struct {
	MXID string `json:"mxid"`
}

var matrixLocalpart = regexp.MustCompile(`^[0-9a-z=_\-./]+$`)

// validateLocalMXID accepts canonical local Matrix user ids only. Billing a remote or malformed
// id can never unlock an account on this Synapse and must not consume a paid seat.
func validateLocalMXID(mxid, serverName string) bool {
	if !strings.HasPrefix(mxid, "@") || serverName == "" {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(mxid, "@"), ":", 2)
	return len(parts) == 2 && parts[1] == serverName && matrixLocalpart.MatchString(parts[0])
}

func (s *Server) handleAddSeat(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found — create one first", http.StatusNotFound)
		return
	}
	var req seatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validateLocalMXID(req.MXID, s.cfg.ServerName) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	exists, err := s.reconciler.synapse.UserExists(r.Context(), req.MXID)
	if err != nil {
		slog.Error("cashier: check seat account", "mxid", req.MXID, "error", err)
		http.Error(w, "could not verify account", http.StatusBadGateway)
		return
	}
	if !exists {
		http.Error(w, "account does not exist on this homeserver", http.StatusBadRequest)
		return
	}
	if err := s.store.AttachSeat(r.Context(), team.ID, req.MXID); err != nil {
		if errors.Is(err, db.ErrSeatCapacityReached) {
			http.Error(w, "no paid seats available — buy more or remove a seat first", http.StatusConflict)
			return
		}
		slog.Error("cashier: insert seat", "error", err)
		http.Error(w, "could not attach seat", http.StatusInternalServerError)
		return
	}
	if err := s.reconciler.ReconcileTeamEntitlement(r.Context(), team.ID); err != nil {
		slog.Error("cashier: reconcile after add seat", "error", err)
		http.Error(w, "seat attached but entitlement sync failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteSeat(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	mxid := r.PathValue("mxid")
	seats, err := s.store.ListSeatsForTeam(r.Context(), team.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	found := false
	for _, seat := range seats {
		if seat.MXID == mxid {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "seat not on your team", http.StatusNotFound)
		return
	}
	// Revoke while the seat is still attached. ReconcileTeamEntitlement only sees current
	// seat rows, so deleting first would leave this MXID outside its revocation set.
	if err := s.reconciler.RevokeSeat(r.Context(), mxid); err != nil {
		slog.Error("cashier: revoke deleted seat", "mxid", mxid, "error", err)
		http.Error(w, "seat removal entitlement sync failed", http.StatusInternalServerError)
		return
	}
	if err := s.store.DeleteSeat(r.Context(), mxid); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type quantityRequest struct {
	Quantity int `json:"quantity"`
}

func (s *Server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	var req quantityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Quantity < 1 {
		http.Error(w, "quantity must be at least 1", http.StatusBadRequest)
		return
	}
	reservation, err := s.store.BeginCheckout(r.Context(), team.ID, req.Quantity, time.Now().UTC())
	if err != nil {
		if errors.Is(err, db.ErrLiveSubscription) {
			http.Error(w, "an active subscription already exists; change the paid seat count instead", http.StatusConflict)
			return
		}
		if errors.Is(err, db.ErrCheckoutInProgress) {
			http.Error(w, "checkout already in progress; finish it or wait for it to expire", http.StatusConflict)
			return
		}
		slog.Error("cashier: reserve checkout", "error", err)
		http.Error(w, "checkout failed", http.StatusInternalServerError)
		return
	}
	resp, err := s.dodo.CheckoutSessions.New(r.Context(), dodo.CheckoutSessionNewParams{
		CheckoutSessionRequest: dodo.CheckoutSessionRequestParam{
			ProductCart: dodo.F([]dodo.ProductItemReqParam{{
				ProductID: dodo.F(s.cfg.DodoProductID),
				Quantity:  dodo.F(int64(req.Quantity)),
			}}),
			Metadata: dodo.F(dodo.MetadataParam{
				"team_id":             shared.UnionString(team.ID.String()),
				"checkout_attempt_id": shared.UnionString(reservation.AttemptID.String()),
			}),
			ReturnURL: dodo.F(s.cfg.PlanPublicURL),
			CancelURL: dodo.F(s.cfg.PlanPublicURL),
		},
	}, option.WithHeader("Idempotency-Key", reservation.AttemptID.String()))
	if err != nil {
		if providerRejectedWithoutApplying(err) {
			if releaseErr := s.store.ReleaseCheckoutReservation(r.Context(), team.ID, reservation.AttemptID); releaseErr != nil {
				slog.Error("cashier: release rejected checkout reservation", "error", releaseErr)
			}
		}
		if !providerRejectedWithoutApplying(err) {
			slog.Warn("cashier: checkout outcome uncertain; reservation retained for idempotent retry", "attempt_id", reservation.AttemptID)
		}
		slog.Error("cashier: create subscription", "error", err)
		http.Error(w, "checkout outcome is pending; retry to safely recover the same attempt", http.StatusBadGateway)
		return
	}

	if resp.CheckoutURL == "" || resp.SessionID == "" {
		slog.Error("cashier: hosted checkout returned incomplete response", "attempt_id", reservation.AttemptID)
		http.Error(w, "checkout outcome is pending; retry to safely recover the same attempt", http.StatusBadGateway)
		return
	}
	if err := s.store.CompleteCheckoutReservation(r.Context(), team.ID, reservation.AttemptID, resp.SessionID); err != nil {
		slog.Error("cashier: record hosted checkout", "error", err)
		http.Error(w, "checkout failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"payment_link": resp.CheckoutURL})
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	if team.DodoCustomerID == nil || *team.DodoCustomerID == "" {
		http.Error(w, "no billing account yet — start checkout first", http.StatusBadRequest)
		return
	}
	session, err := s.dodo.Customers.CustomerPortal.New(r.Context(), *team.DodoCustomerID, dodo.CustomerCustomerPortalNewParams{
		ReturnURL: dodo.F(s.cfg.PlanPublicURL),
	})
	if err != nil {
		slog.Error("cashier: customer portal", "error", err)
		http.Error(w, "portal unavailable", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"link": session.Link})
}

func (s *Server) handleChangeSeatCount(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	var req quantityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Quantity < 1 {
		http.Error(w, "quantity must be at least 1", http.StatusBadRequest)
		return
	}
	if (team.SubscriptionStatus != "active" && team.SubscriptionStatus != "on_hold") || team.DodoSubscriptionID == nil || *team.DodoSubscriptionID == "" {
		http.Error(w, "no active subscription", http.StatusBadRequest)
		return
	}
	if req.Quantity == team.PaidSeats {
		writeJSON(w, http.StatusOK, map[string]string{"status": "unchanged"})
		return
	}
	reservation, err := s.store.ReserveSeatCountChange(r.Context(), team.ID, req.Quantity, time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, db.ErrSeatCapacityReached):
			need := reservation.Attached - req.Quantity
			http.Error(w, fmt.Sprintf("remove %d seat(s) before lowering to %d paid seats", need, req.Quantity), http.StatusConflict)
		case errors.Is(err, db.ErrSeatCountChangeInProgress):
			http.Error(w, "another seat count change is awaiting its billing webhook", http.StatusConflict)
		case errors.Is(err, db.ErrLiveSubscription):
			http.Error(w, "no active subscription", http.StatusBadRequest)
		default:
			slog.Error("cashier: reserve seat count change", "error", err)
			http.Error(w, "seat count change failed", http.StatusInternalServerError)
		}
		return
	}
	err = s.dodo.Subscriptions.ChangePlan(r.Context(), *team.DodoSubscriptionID, dodo.SubscriptionChangePlanParams{
		UpdateSubscriptionPlanReq: dodo.UpdateSubscriptionPlanReqParam{
			ProductID:            dodo.F(s.cfg.DodoProductID),
			Quantity:             dodo.F(int64(req.Quantity)),
			ProrationBillingMode: dodo.F(dodo.UpdateSubscriptionPlanReqProrationBillingModeProratedImmediately),
			EffectiveAt:          dodo.F(dodo.UpdateSubscriptionPlanReqEffectiveAtImmediately),
			OnPaymentFailure:     dodo.F(dodo.UpdateSubscriptionPlanReqOnPaymentFailurePreventChange),
		},
	}, option.WithHeader("Idempotency-Key", reservation.AttemptID.String()))
	if err != nil {
		if providerRejectedWithoutApplying(err) {
			if releaseErr := s.store.ReleaseSeatCountChange(r.Context(), team.ID, reservation.AttemptID); releaseErr != nil {
				slog.Error("cashier: release rejected seat count change", "error", releaseErr)
			}
		} else {
			slog.Warn("cashier: seat count outcome uncertain; reservation retained for idempotent retry", "attempt_id", reservation.AttemptID)
		}
		slog.Error("cashier: change plan", "error", err)
		http.Error(w, "seat count outcome is pending; retry the same quantity or reconcile provider state", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pending_webhook"})
}

func providerRejectedWithoutApplying(err error) bool {
	var apiErr *dodo.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusPaymentRequired,
		http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusNotAcceptable, http.StatusGone, http.StatusLengthRequired,
		http.StatusRequestEntityTooLarge, http.StatusRequestURITooLong,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

// handleReconcileSeatCount is an authenticated recovery path for a successful provider change
// whose webhook was delayed or lost. It reads Dodo's subscription snapshot, requires the exact
// reserved quantity and product, then applies the same idempotent state transition as a webhook.
func (s *Server) handleReconcileSeatCount(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	if team.PendingPaidSeats == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "nothing_pending"})
		return
	}
	if team.DodoSubscriptionID == nil || *team.DodoSubscriptionID == "" {
		http.Error(w, "no provider subscription to reconcile", http.StatusConflict)
		return
	}
	sub, err := s.dodo.Subscriptions.Get(r.Context(), *team.DodoSubscriptionID)
	if err != nil {
		slog.Error("cashier: retrieve subscription for reconciliation", "error", err)
		http.Error(w, "provider state unavailable", http.StatusBadGateway)
		return
	}
	if err := s.validateSubscriptionProduct(*sub); err != nil {
		http.Error(w, "provider product does not match this environment", http.StatusConflict)
		return
	}
	if int(sub.Quantity) != *team.PendingPaidSeats {
		http.Error(w, "provider has not applied the reserved seat count yet; retry the same quantity first", http.StatusConflict)
		return
	}
	status := string(sub.Status)
	switch status {
	case "active", "on_hold", "failed", "cancelled", "expired":
	default:
		http.Error(w, "provider change is not terminal yet", http.StatusConflict)
		return
	}
	if err := s.bindSubscription(r.Context(), team.ID, *sub, status); err != nil {
		http.Error(w, "could not reconcile provider state", http.StatusConflict)
		return
	}
	switch status {
	case "active", "on_hold":
		err = s.reconciler.ReconcileTeamEntitlement(r.Context(), team.ID)
	case "failed", "cancelled", "expired":
		err = s.reconciler.ClearAllTeamSeats(r.Context(), team.ID)
	}
	if err != nil {
		slog.Error("cashier: reconcile entitlement from provider snapshot", "error", err)
		http.Error(w, "provider state saved but entitlement sync failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reconciled"})
}

func (s *Server) handleDodoWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	event, err := s.dodo.Webhooks.Unwrap(body, r.Header)
	if err != nil {
		slog.Error("cashier: webhook unwrap", "error", err)
		http.Error(w, "invalid webhook", http.StatusBadRequest)
		return
	}

	webhookID := r.Header.Get("webhook-id")
	dedupKey := s.webhookDedupKey(webhookID)
	if webhookID != "" {
		processed, err := s.store.IsWebhookProcessed(r.Context(), dedupKey)
		if err != nil {
			slog.Error("cashier: webhook dedup check", "error", err)
			http.Error(w, "webhook state unavailable", http.StatusServiceUnavailable)
			return
		} else if processed {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	if err := s.processWebhook(r.Context(), event); err != nil {
		slog.Error("cashier: process webhook", "error", err, "type", event.Type)
		if errors.Is(err, errUnexpectedDodoProduct) {
			http.Error(w, "webhook product does not match this environment", http.StatusBadRequest)
			return
		}
		http.Error(w, "processing failed", http.StatusInternalServerError)
		return
	}

	if webhookID != "" {
		if err := s.store.MarkWebhookProcessed(r.Context(), dedupKey); err != nil {
			slog.Error("cashier: mark webhook processed", "error", err)
			// The provider should retry. Event processing is idempotent, while acknowledging a
			// webhook whose durable dedupe mark was lost could silently skip a later retry.
			http.Error(w, "webhook state unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) webhookDedupKey(webhookID string) string {
	if s.cfg == nil {
		return "unconfigured:" + webhookID
	}
	return s.cfg.TelecryptEnv + ":" + webhookID
}

var (
	errStaleSubscriptionEvent = errors.New("stale subscription event")
	errUnexpectedDodoProduct  = errors.New("unexpected Dodo product")
)

func (s *Server) validateSubscriptionProduct(sub dodo.Subscription) error {
	if s.cfg == nil || s.cfg.DodoProductID == "" {
		return errors.New("cashier Dodo product is not configured")
	}
	if sub.ProductID != s.cfg.DodoProductID {
		return fmt.Errorf("%w: got %q", errUnexpectedDodoProduct, sub.ProductID)
	}
	return nil
}

func (s *Server) processWebhook(ctx context.Context, event *dodo.UnwrapWebhookEvent) (err error) {
	// Dodo delivers asynchronously and older subscriptions can emit late terminal/renewal
	// events. Once a team is bound to a newer subscription, an old event must be acknowledged
	// but must never overwrite the newer entitlement state (or trigger endless retries).
	defer func() {
		if errors.Is(err, errStaleSubscriptionEvent) {
			slog.Warn("cashier: ignored stale subscription event", "type", event.Type)
			err = nil
		}
	}()
	switch event.Type {
	case dodo.UnwrapWebhookEventTypeSubscriptionActive:
		ev, ok := event.AsUnion().(dodo.SubscriptionActiveWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected active union")
		}
		return s.handleSubscriptionEntitlement(ctx, ev.Data, "active")

	case dodo.UnwrapWebhookEventTypeSubscriptionRenewed:
		ev, ok := event.AsUnion().(dodo.SubscriptionRenewedWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected renewed union")
		}
		return s.handleSubscriptionEntitlement(ctx, ev.Data, "active")

	case dodo.UnwrapWebhookEventTypeSubscriptionUpdated:
		ev, ok := event.AsUnion().(dodo.SubscriptionUpdatedWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected updated union")
		}
		return s.handleSubscriptionEntitlement(ctx, ev.Data, string(ev.Data.Status))

	case dodo.UnwrapWebhookEventTypeSubscriptionOnHold:
		ev, ok := event.AsUnion().(dodo.SubscriptionOnHoldWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected on_hold union")
		}
		return s.updateTeamStatusOnly(ctx, ev.Data, "on_hold")

	case dodo.UnwrapWebhookEventTypeSubscriptionFailed:
		ev, ok := event.AsUnion().(dodo.SubscriptionFailedWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected failed union")
		}
		return s.handleSubscriptionRevocation(ctx, ev.Data, "failed")

	case dodo.UnwrapWebhookEventTypeSubscriptionCancelled:
		ev, ok := event.AsUnion().(dodo.SubscriptionCancelledWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected cancelled union")
		}
		return s.handleSubscriptionRevocation(ctx, ev.Data, "cancelled")

	case dodo.UnwrapWebhookEventTypeSubscriptionExpired:
		ev, ok := event.AsUnion().(dodo.SubscriptionExpiredWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected expired union")
		}
		return s.handleSubscriptionRevocation(ctx, ev.Data, "expired")

	default:
		return nil
	}
}

// handleSubscriptionRevocation makes all terminal Dodo states revoke access. The team status is
// persisted first so a retry (or a later periodic reconciliation) still sees an inactive
// subscription if Synapse is temporarily unavailable.
func (s *Server) handleSubscriptionRevocation(ctx context.Context, sub dodo.Subscription, status string) error {
	if err := s.validateSubscriptionProduct(sub); err != nil {
		return err
	}
	team, err := s.teamForSubscription(ctx, sub)
	if err != nil {
		return err
	}
	if err := s.bindSubscription(ctx, team.ID, sub, status); err != nil {
		return err
	}
	return s.reconciler.ClearAllTeamSeats(ctx, team.ID)
}

func (s *Server) handleSubscriptionEntitlement(ctx context.Context, sub dodo.Subscription, status string) error {
	if err := s.validateSubscriptionProduct(sub); err != nil {
		return err
	}
	team, err := s.teamForSubscription(ctx, sub)
	if err != nil {
		return err
	}
	if err := s.bindSubscription(ctx, team.ID, sub, status); err != nil {
		return err
	}
	return s.reconciler.ReconcileTeamEntitlement(ctx, team.ID)
}

func (s *Server) updateTeamStatusOnly(ctx context.Context, sub dodo.Subscription, status string) error {
	if err := s.validateSubscriptionProduct(sub); err != nil {
		return err
	}
	team, err := s.teamForSubscription(ctx, sub)
	if err != nil {
		return err
	}
	return s.bindSubscription(ctx, team.ID, sub, status)
}

func (s *Server) bindSubscription(ctx context.Context, teamID uuid.UUID, sub dodo.Subscription, status string) error {
	if err := s.store.BindCurrentSubscription(ctx, teamID, sub.SubscriptionID, sub.Customer.CustomerID, status, int(sub.Quantity)); err != nil {
		if errors.Is(err, db.ErrStaleSubscription) {
			return errStaleSubscriptionEvent
		}
		return err
	}
	return nil
}

func (s *Server) teamForSubscription(ctx context.Context, sub dodo.Subscription) (db.Team, error) {
	if sub.SubscriptionID != "" {
		if binding, found, err := s.store.GetSubscriptionBinding(ctx, sub.SubscriptionID); err != nil {
			return db.Team{}, err
		} else if found {
			if !binding.IsCurrent {
				return db.Team{}, errStaleSubscriptionEvent
			}
			return s.store.GetTeamByID(ctx, binding.TeamID)
		}
	}
	if teamID := metadataString(sub.Metadata, "team_id"); teamID != "" {
		id, err := uuid.Parse(teamID)
		if err != nil {
			return db.Team{}, fmt.Errorf("invalid team_id metadata: %w", err)
		}
		team, err := s.store.GetTeamByID(ctx, id)
		if err != nil {
			return db.Team{}, err
		}
		// Metadata is accepted only for the first event of the exact durable checkout
		// attempt that created it. This prevents a late webhook from an abandoned checkout
		// from binding while a replacement checkout happens to be pending.
		attemptID, err := uuid.Parse(metadataString(sub.Metadata, "checkout_attempt_id"))
		if err != nil || sub.SubscriptionID == "" || team.SubscriptionStatus != "pending" ||
			team.CheckoutAttemptID == nil || *team.CheckoutAttemptID != attemptID {
			return db.Team{}, errStaleSubscriptionEvent
		}
		return team, nil
	}
	return db.Team{}, errors.New("team not found for subscription")
}

func metadataString(meta dodo.Metadata, key string) string {
	v, ok := meta[key]
	if !ok {
		return ""
	}
	if s, ok := v.(shared.UnionString); ok {
		return string(s)
	}
	return fmt.Sprint(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func NewDodoClient(cfg *config.CashierConfig) *dodo.Client {
	opts := []option.RequestOption{
		option.WithBaseURL(cfg.DodoAPIBase),
		option.WithBearerToken(cfg.DodoAPIKey),
		option.WithWebhookKey(cfg.DodoWebhookSecret),
	}
	if cfg.TelecryptEnv == "test" {
		opts = append(opts, option.WithEnvironmentTestMode())
	} else {
		opts = append(opts, option.WithEnvironmentLiveMode())
	}
	client := dodo.NewClient(opts...)
	return client
}

var planTmpl = template.Must(template.New("plan").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TeleCrypt Plan</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; }
table { border-collapse: collapse; width: 100%; }
td, th { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }
button { margin-top: 0.5rem; }
.note { color: #555; font-size: 0.9rem; }
.sandbox { border: 2px solid #a16207; background: #fef3c7; color: #713f12; padding: 0.8rem; margin-bottom: 1rem; }
.danger { color: #991b1b; }
.actions { white-space: nowrap; }
</style>
</head>
<body>
<h1>TeleCrypt Plan</h1>
{{if .TestMode}}
<section class="sandbox" role="status">
<strong>TEST / SANDBOX — no real charges</strong>
<p>This Plan uses Dodo test mode. At Dodo's hosted checkout use test Visa
<code>4242 4242 4242 4242</code>, expiry <code>06/32</code>, CVV <code>123</code>.
Never enter a real card in this environment.</p>
</section>
{{end}}
{{if not .LoggedIn}}
<p>Registration is free and does not require a card.</p>
<p><a href="{{.RegisterURL}}">Create a TeleCrypt account</a> or
<a href="/plan/login">log in</a> to manage a team and its bot seats.</p>
{{else}}
<p>Signed in as <strong>{{.MXID}}</strong></p>
{{if .Team}}
<p>Subscription: <strong>{{.Team.SubscriptionStatus}}</strong> · Paid seats:
<strong>{{.Team.PaidSeats}}</strong> · Attached accounts: <strong>{{len .Seats}}</strong></p>
<h2>Seats</h2>
{{if .Seats}}
<table><tr><th>MXID</th><th>Attached</th><th>Action</th></tr>
{{range .Seats}}<tr><td>{{.MXID}}</td><td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
<td class="actions"><button type="button" data-mxid="{{.MXID}}" onclick="removeSeat(this.dataset.mxid)">Remove</button></td></tr>{{end}}
</table>
{{else}}<p>No seats attached yet.</p>{{end}}
<form id="add-seat" onsubmit="return addSeat(event)">
<label>Bot or account MXID: <input name="mxid" required placeholder="@bot:telecrypt.io" autocomplete="off"></label>
<button type="submit">Attach seat</button>
</form>
<p class="note">Only an existing local TeleCrypt account can be attached. Removing a seat revokes
its cashier-managed paid capabilities immediately; manual operator grants are preserved.</p>
{{if .CanCheckout}}
<form id="checkout" onsubmit="return checkout(event)">
<label>Paid seats: <input name="quantity" type="number" min="1" value="{{if gt .Team.PaidSeats 0}}{{.Team.PaidSeats}}{{else}}1{{end}}" required></label>
<button type="submit">{{if $.TestMode}}Start sandbox checkout{{else}}Start checkout{{end}}</button>
</form>
<p class="note">Card entry and payment details are handled only by Dodo's hosted checkout.</p>
{{else if .CheckoutActive}}
<p><strong>Checkout is in progress.</strong> Finish the existing Dodo checkout. If the browser
lost Dodo's response, retry below: the same durable idempotency key recovers the same checkout
instead of creating another subscription.</p>
<form id="checkout-retry" onsubmit="return checkout(event)">
<input name="quantity" type="hidden" value="{{.Team.PaidSeats}}">
<button type="submit">Recover existing checkout</button>
</form>
{{else if .CanChangeSeats}}
<form id="seat-count" onsubmit="return changeSeatCount(event)">
<label>Paid seats: <input name="quantity" type="number" min="1" value="{{if .Team.PendingPaidSeats}}{{.Team.PendingPaidSeats}}{{else}}{{.Team.PaidSeats}}{{end}}" required></label>
<button type="submit">Update paid seats</button>
</form>
<p class="note">Increases and valid decreases change the existing subscription. To reduce below
the attached count, remove seats first; TeleCrypt never chooses and detaches a bot automatically.</p>
{{if .Team.PendingPaidSeats}}
<p><strong>A change to {{.Team.PendingPaidSeats}} paid seat(s) is awaiting confirmation.</strong>
Retry the same quantity to recover an uncertain provider response, or read the current provider
subscription state if its webhook was missed.</p>
<button type="button" onclick="reconcileSeatCount()">Reconcile provider state</button>
{{end}}
{{end}}
{{if .Team.DodoCustomerID}}
<button type="button" onclick="openPortal()">Manage subscription, card, invoices, or cancellation</button>
<p class="note">Dodo's hosted customer portal handles saved payment methods, invoices, and
cancellation. Seat quantity is managed above so downgrade safety remains enforced here.</p>
{{end}}
{{else}}
<p>No team yet.</p>
<button type="button" onclick="createTeam()">Create team</button>
{{end}}
{{end}}
<script>
async function createTeam() {
  const r = await fetch('/api/team', {method:'POST'});
  if (r.ok) location.reload(); else alert(await r.text());
}
async function addSeat(e) {
  e.preventDefault();
  const mxid = e.target.mxid.value.trim();
  const r = await fetch('/api/team/seats', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({mxid})});
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}
async function removeSeat(mxid) {
  if (!confirm('Remove ' + mxid + ' from this team and revoke its paid capabilities?')) return;
  const r = await fetch('/api/team/seats/' + encodeURIComponent(mxid), {method:'DELETE'});
  if (r.ok) location.reload(); else alert(await r.text());
}
async function checkout(e) {
  e.preventDefault();
  const quantity = parseInt(e.target.quantity.value, 10);
  const r = await fetch('/api/team/checkout', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({quantity})});
  if (!r.ok) { alert(await r.text()); return false; }
  const j = await r.json();
  if (j.payment_link) window.location = j.payment_link; else alert('no payment link');
  return false;
}
async function openPortal() {
  const r = await fetch('/api/team/portal', {method:'POST'});
  if (!r.ok) { alert(await r.text()); return; }
  const j = await r.json();
  if (j.link) window.open(j.link, '_blank');
}
async function changeSeatCount(e) {
  e.preventDefault();
  const quantity = parseInt(e.target.quantity.value, 10);
  const r = await fetch('/api/team/seat-count', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({quantity})});
  if (r.ok) {
    alert('Seat-count change submitted. The signed Dodo webhook will update this page shortly.');
    location.reload();
  } else {
    alert(await r.text());
  }
  return false;
}
async function reconcileSeatCount() {
  const r = await fetch('/api/team/seat-count/reconcile', {method:'POST'});
  if (r.ok) {
    location.reload();
  } else {
    alert(await r.text());
  }
}
</script>
</body>
</html>`))
