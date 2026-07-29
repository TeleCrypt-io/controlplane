// Package janitor implements janitor's one sweep: lock stale unclaimed agent accounts via MAS's
// admin API, and email the owner a digest of new human sign-ups awaiting review. See cmd/janitor
// for wiring and internal/masadmin for the MAS admin client this is built on.
package janitor

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

// digestHighWaterKey is the internal/db locker_state row this package reads/advances.
const digestHighWaterKey = "digest_high_water"

// Config holds one Sweeper's tunables — see cmd/janitor for how these map to env vars.
type Config struct {
	// LockAfterHours: an account must be at least this old, unclaimed, and email-less to be
	// locked.
	LockAfterHours int
	// ServerName is the Matrix server name used to turn a MAS username into an MXID
	// (@username:ServerName).
	ServerName string
	// ExcludeMXIDs is a defensive belt-and-suspenders exclusion list (service accounts like the
	// service accounts) — checked unconditionally regardless of what else would otherwise match.
	ExcludeMXIDs map[string]bool
	// DryRun logs every action this sweep would take (lock or send) without doing it. In dry-run,
	// the digest high-water mark is not advanced either — nothing was actually delivered.
	DryRun bool
	// OwnerEmail is the digest's recipient. If empty, the digest half of the sweep is skipped
	// entirely (logged as a warning) — the lock half still runs.
	OwnerEmail string
}

// masAdminClient is the subset of *masadmin.Client that Sweeper needs. Defined here (not in
// package masadmin) so tests can supply a fake without necessarily driving a real MAS instance —
// though this package's own tests do exercise the real *masadmin.Client against an httptest fake
// server, per the task's test requirements.
type masAdminClient interface {
	ListUsers(ctx context.Context) ([]masadmin.User, error)
	ListUserEmails(ctx context.Context) ([]masadmin.UserEmail, error)
	LockUser(ctx context.Context, userID string) (time.Time, error)
	UnlockUser(ctx context.Context, userID string) error
}

// store is the subset of *db.Store that Sweeper needs.
type store interface {
	VerifiedMXIDs(ctx context.Context) (map[string]bool, error)
	IsVerified(ctx context.Context, mxid string) (bool, error)
	JanitorLockState(ctx context.Context) (confirmed, pending map[string]time.Time, err error)
	BeginJanitorLock(ctx context.Context, userID string) (time.Time, error)
	ConfirmJanitorLock(ctx context.Context, userID string, lockedAt time.Time) error
	DeleteJanitorLock(ctx context.Context, userID string) error
	LockerHighWaterMark(ctx context.Context, key string) (time.Time, bool, error)
	SetLockerHighWaterMark(ctx context.Context, key string, value time.Time) error
}

// Mailer is the subset of email-sending behavior Sweeper needs — see SMTPMailer (real SMTP) and
// LogMailer (degraded fallback when SMTP isn't configured) in mailer.go.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Sweeper runs janitor's sweep against one MAS deployment and one controlplane database.
type Sweeper struct {
	mas    masAdminClient
	store  store
	mailer Mailer
	cfg    Config
}

func NewSweeper(mas masAdminClient, store store, mailer Mailer, cfg Config) *Sweeper {
	return &Sweeper{mas: mas, store: store, mailer: mailer, cfg: cfg}
}

// Sweep runs one full pass: lock stale unclaimed agent accounts, then — independently, a digest
// failure never undoes or blocks the lock half above it — email the owner a digest of new human
// sign-ups awaiting review.
//
// Only returns an error for failures in the shared setup both halves depend on (listing MAS users
// / emails, reading the verified set and lock provenance): without those, no lock or skip decision
// can be made safely, so the sweep fails closed rather than guessing. Per-account lock/unlock
// failures and digest failures are logged, not returned — see sweepLocks and sweepDigest.
func (s *Sweeper) Sweep(ctx context.Context) error {
	users, err := s.mas.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("janitor: list users: %w", err)
	}
	emails, err := s.mas.ListUserEmails(ctx)
	if err != nil {
		return fmt.Errorf("janitor: list user emails: %w", err)
	}
	hasEmail := make(map[string]bool, len(emails))
	for _, e := range emails {
		hasEmail[e.UserID] = true
	}

	verified, err := s.store.VerifiedMXIDs(ctx)
	if err != nil {
		return fmt.Errorf("janitor: load verified mxids: %w", err)
	}
	janitorLocked, pendingLocks, err := s.store.JanitorLockState(ctx)
	if err != nil {
		return fmt.Errorf("janitor: load lock state: %w", err)
	}

	s.sweepLocks(ctx, users, hasEmail, verified, janitorLocked, pendingLocks)

	if err := s.sweepDigest(ctx, users, hasEmail); err != nil {
		slog.Error("janitor: digest failed", "error", err)
	}

	return nil
}

func (s *Sweeper) mxid(username string) string {
	return fmt.Sprintf("@%s:%s", username, s.cfg.ServerName)
}

// sweepLocks locks every account that is stale, unclaimed, and email-less, and repairs a verified
// account only when persisted provenance proves janitor created its current lock. The full
// verified set is an efficient first-pass snapshot, but a candidate is checked again immediately
// around the external MAS mutation. That closes the ordinary snapshot race and makes a race that
// lands during LockUser convergent via compensation. Errors acting on one account are logged and
// don't stop the rest of the sweep.
func (s *Sweeper) sweepLocks(
	ctx context.Context,
	users []masadmin.User,
	hasEmail, verified map[string]bool,
	janitorLocked, pendingLocks map[string]time.Time,
) {
	cutoff := time.Now().Add(-time.Duration(s.cfg.LockAfterHours) * time.Hour)
	locked, unlocked, skipped := 0, 0, 0

	for _, u := range users {
		mxid := s.mxid(u.Username)
		log := slog.With("mxid", mxid, "user_id", u.ID)
		confirmedAt, confirmed := janitorLocked[u.ID]
		pendingAt, pending := pendingLocks[u.ID]

		// Deactivation is an independent operator/security state. Never erase its accompanying
		// lock. Relinquish janitor provenance so a later operator reactivation cannot make that
		// same lock eligible for automatic entitlement repair.
		if u.DeactivatedAt != nil {
			if confirmed || pending {
				if s.cfg.DryRun {
					log.Info("would relinquish janitor lock state for deactivated account (dry run)")
				} else if err := s.store.DeleteJanitorLock(ctx, u.ID); err != nil {
					log.Error("failed to relinquish janitor lock state for deactivated account", "error", err)
				} else {
					delete(janitorLocked, u.ID)
					delete(pendingLocks, u.ID)
				}
			}
			log.Debug("skip lock", "reason", "deactivated")
			skipped++
			continue
		}

		if u.LockedAt != nil {
			// A durable intent plus a locked MAS account means an earlier call committed but
			// crashed/lost its response before confirmation. Adopt the exact observed timestamp.
			if pending {
				if u.LockedAt.Before(pendingAt) {
					// The lock predates our durable intent, so an operator won the race between
					// the MAS list snapshot and LockUser. Relinquish intent; never adopt/unlock it.
					if s.cfg.DryRun {
						log.Info("would clear intent for pre-existing external lock (dry run)")
					} else if err := s.store.DeleteJanitorLock(ctx, u.ID); err != nil {
						log.Error("failed to clear intent for pre-existing external lock", "error", err)
					} else {
						delete(pendingLocks, u.ID)
					}
					log.Debug("skip lock", "reason", "external lock predates janitor intent")
					skipped++
					continue
				}
				if s.cfg.DryRun {
					log.Info("would confirm pending janitor lock (dry run)")
				} else if err := s.store.ConfirmJanitorLock(ctx, u.ID, *u.LockedAt); err != nil {
					log.Error("failed to confirm pending janitor lock; leaving lock unchanged", "error", err)
					skipped++
					continue
				}
				confirmedAt, confirmed = *u.LockedAt, true
				janitorLocked[u.ID] = *u.LockedAt
				delete(pendingLocks, u.ID)
			}

			if !confirmed || !u.LockedAt.Equal(confirmedAt) {
				// A differing locked_at proves an unlock/relock cycle created a new external lock.
				// Clear stale janitor state but never unlock the current security/operator lock.
				if confirmed {
					if s.cfg.DryRun {
						log.Info("would clear stale janitor provenance for newer external lock (dry run)")
					} else if err := s.store.DeleteJanitorLock(ctx, u.ID); err != nil {
						log.Error("failed to clear stale janitor provenance", "error", err)
					} else {
						delete(janitorLocked, u.ID)
						delete(pendingLocks, u.ID)
					}
				}
				log.Debug("skip lock", "reason", "already locked outside janitor")
				skipped++
				continue
			}
			isVerified, err := s.store.IsVerified(ctx, mxid)
			if err != nil {
				log.Error("verification recheck failed; leaving existing lock unchanged", "error", err)
				skipped++
				continue
			}
			if !isVerified {
				log.Debug("skip lock", "reason", "already locked")
				skipped++
				continue
			}
			if s.cfg.DryRun {
				log.Info("would unlock verified account (dry run)")
				unlocked++
				continue
			}
			if err := s.mas.UnlockUser(ctx, u.ID); err != nil {
				log.Error("verified-account unlock failed", "error", err)
				continue
			}
			if err := s.store.DeleteJanitorLock(ctx, u.ID); err != nil {
				log.Error("unlocked verified account but failed to clear lock provenance", "error", err)
			} else {
				delete(janitorLocked, u.ID)
			}
			log.Info("unlocked verified account")
			unlocked++
			continue
		}

		if confirmed || pending {
			if s.cfg.DryRun {
				log.Info("would clear stale janitor lock state (dry run)")
			} else {
				if err := s.store.DeleteJanitorLock(ctx, u.ID); err != nil {
					log.Error("failed to clear stale lock state; refusing further action", "error", err)
					skipped++
					continue
				}
				log.Info("cleared stale janitor lock state from unlocked account")
			}
			// Update only the in-memory sweep snapshot in dry-run so later classification
			// accurately models the action without mutating persisted state.
			delete(janitorLocked, u.ID)
			delete(pendingLocks, u.ID)
		}

		reason := skipReason(u, cutoff, mxid, hasEmail, verified, s.cfg.ExcludeMXIDs)
		if reason != "" {
			log.Debug("skip lock", "reason", reason)
			skipped++
			continue
		}

		isVerified, err := s.store.IsVerified(ctx, mxid)
		if err != nil {
			log.Error("verification recheck failed; refusing to lock", "error", err)
			skipped++
			continue
		}
		if isVerified {
			log.Debug("skip lock", "reason", "verified on pre-lock recheck")
			skipped++
			continue
		}

		if s.cfg.DryRun {
			log.Info("would lock (dry run)", "reason", "stale, unclaimed, no email", "created_at", u.CreatedAt)
			locked++
			continue
		}

		intentAt, err := s.store.BeginJanitorLock(ctx, u.ID)
		if err != nil {
			log.Error("failed to persist pre-lock intent; refusing to lock", "error", err)
			continue
		}
		pendingLocks[u.ID] = intentAt

		lockedAt, err := s.mas.LockUser(ctx, u.ID)
		if err != nil {
			// Keep the durable intent: the HTTP result is ambiguous, and the next sweep will
			// either clear it if MAS stayed unlocked or confirm the exact observed locked_at.
			log.Error("lock failed", "error", err)
			continue
		}
		if lockedAt.Before(intentAt) {
			// MAS lock is idempotent. A timestamp older than our pre-call intent proves an
			// operator locked the user after the list snapshot but before this POST.
			log.Warn("external lock won pre-call race; refusing janitor ownership",
				"locked_at", lockedAt, "intent_at", intentAt)
			if err := s.store.DeleteJanitorLock(ctx, u.ID); err != nil {
				log.Error("failed to clear intent after external lock race", "error", err)
			} else {
				delete(pendingLocks, u.ID)
			}
			skipped++
			continue
		}
		log.Info("locked stale unclaimed account", "reason", "stale, unclaimed, no email", "created_at", u.CreatedAt)
		if err := s.store.ConfirmJanitorLock(ctx, u.ID, lockedAt); err != nil {
			// The pre-lock intent remains durable and is enough for a later sweep to adopt the
			// exact timestamp. Continue to the post-lock entitlement check now.
			log.Error("failed to confirm lock provenance; pending intent retained", "error", err)
		} else {
			janitorLocked[u.ID] = lockedAt
			delete(pendingLocks, u.ID)
		}

		// A grant may have committed after the pre-lock read but during the external MAS call.
		// Restore the pre-sweep unlocked state unless a post-lock read proves the account remains
		// unverified. A failed read also compensates: janitor cleanup must not leave a possibly
		// entitled account newly locked just because its own database became unavailable.
		isVerified, err = s.store.IsVerified(ctx, mxid)
		if err == nil && !isVerified {
			locked++
			continue
		}
		if err != nil {
			log.Error("post-lock verification failed; compensating unlock", "error", err)
		} else {
			log.Info("verification appeared during lock; compensating unlock")
		}
		if err := s.mas.UnlockUser(ctx, u.ID); err != nil {
			log.Error("compensating unlock failed", "error", err)
			continue
		}
		if err := s.store.DeleteJanitorLock(ctx, u.ID); err != nil {
			log.Error("compensating unlock succeeded but lock state cleanup failed", "error", err)
		} else {
			delete(janitorLocked, u.ID)
			delete(pendingLocks, u.ID)
		}
		unlocked++
	}

	slog.Info("janitor: lock sweep complete",
		"locked", locked, "unlocked", unlocked, "skipped", skipped,
		"considered", len(users), "dry_run", s.cfg.DryRun)
}

// skipReason returns why u should NOT be locked, or "" if it should be.
func skipReason(u masadmin.User, cutoff time.Time, mxid string, hasEmail, verified, excluded map[string]bool) string {
	switch {
	case u.DeactivatedAt != nil:
		return "deactivated"
	case !u.CreatedAt.Before(cutoff):
		return "not stale yet"
	case hasEmail[u.ID]:
		return "has email (human awaiting review)"
	case verified[mxid]:
		return "verified"
	case excluded[mxid]:
		return "excluded via EXCLUDE_MXIDS"
	default:
		return ""
	}
}

// sweepDigest emails (or, in degraded/dry-run mode, logs) new human sign-ups — accounts with an
// email attached, created after the last successful digest's high-water mark. The mark only
// advances after a confirmed send (SMTPMailer) or a confirmed log-in-lieu-of-send (LogMailer) —
// never on a dry run and never on a real send error — so a crashed run can duplicate a window at
// worst, never silently drop one.
func (s *Sweeper) sweepDigest(ctx context.Context, users []masadmin.User, hasEmail map[string]bool) error {
	if s.cfg.OwnerEmail == "" {
		slog.Warn("janitor: OWNER_EMAIL not set, skipping digest")
		return nil
	}

	highWater, found, err := s.store.LockerHighWaterMark(ctx, digestHighWaterKey)
	if err != nil {
		return fmt.Errorf("read high-water mark: %w", err)
	}
	if !found {
		highWater = time.Unix(0, 0).UTC()
	}

	type candidate struct {
		mxid      string
		createdAt time.Time
	}
	var candidates []candidate
	newMark := highWater
	for _, u := range users {
		if !hasEmail[u.ID] {
			continue
		}
		if !u.CreatedAt.After(highWater) {
			continue
		}
		candidates = append(candidates, candidate{mxid: s.mxid(u.Username), createdAt: u.CreatedAt})
		if u.CreatedAt.After(newMark) {
			newMark = u.CreatedAt
		}
	}

	if len(candidates) == 0 {
		slog.Info("janitor: digest: no new human sign-ups since last digest")
		return nil
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].createdAt.Before(candidates[j].createdAt) })

	// CRLF throughout: net/smtp writes this body verbatim over DATA (no newline normalization),
	// and RFC 5322 requires CRLF line endings — bare LF is technically non-conformant and some
	// servers mangle or reject it.
	var body strings.Builder
	fmt.Fprintf(&body, "%d new human sign-up(s) awaiting review:\r\n\r\n", len(candidates))
	for _, c := range candidates {
		fmt.Fprintf(&body, "%s  created %s\r\n", c.mxid, c.createdAt.Format(time.RFC3339))
	}

	if s.cfg.DryRun {
		slog.Info("janitor: digest: would send (dry run)", "count", len(candidates))
		return nil
	}

	subject := fmt.Sprintf("TeleCrypt.io: %d new sign-up(s) awaiting review", len(candidates))
	if err := s.mailer.Send(ctx, s.cfg.OwnerEmail, subject, body.String()); err != nil {
		return fmt.Errorf("send digest: %w", err)
	}

	if err := s.store.SetLockerHighWaterMark(ctx, digestHighWaterKey, newMark); err != nil {
		return fmt.Errorf("advance high-water mark: %w", err)
	}

	slog.Info("janitor: digest sent", "count", len(candidates), "new_high_water", newMark)
	return nil
}
