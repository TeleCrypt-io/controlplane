// Command janitor is TeleCrypt.io's one deployed process holding a standing MAS admin
// credential. Once per day (systemd timer, RUN_ONCE=1) — or on-demand for ops/testing — it
// locks stale unclaimed agent accounts via MAS's admin API (internal/masadmin) and emails the
// owner a digest of new human sign-ups awaiting review (internal/janitor). DRY_RUN=1 logs every
// action it would take without doing it.
//
// janitor opens NO listening network port of any kind: zero inbound attack surface. This is
// deliberate — it's the one binary in this repo privileged enough that a listening port on it
// would matter.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/janitor"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

func main() {
	cfg, err := config.LoadLocker()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.ControlplaneDBURL)
	if err != nil {
		slog.Error("db connect", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("migrate", "error", err)
		os.Exit(1)
	}

	sweeper := build(cfg, pool)

	if cfg.RunOnce {
		if err := sweeper.Sweep(ctx); err != nil {
			slog.Error("sweep", "error", err)
			os.Exit(1)
		}
		return
	}

	interval := time.Duration(cfg.SweepIntervalSec) * time.Second
	slog.Info("janitor started", "interval", interval, "dry_run", cfg.DryRun)

	if err := sweeper.Sweep(ctx); err != nil {
		slog.Error("sweep", "error", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return
		case <-ticker.C:
			if err := sweeper.Sweep(ctx); err != nil {
				slog.Error("sweep", "error", err)
			}
		}
	}
}

func build(cfg *config.LockerConfig, pool *pgxpool.Pool) *janitor.Sweeper {
	masClient := masadmin.NewClient(cfg.MASBaseURL, cfg.MASAdminClientID, cfg.MASAdminClientSecret)
	store := db.NewStore(pool)

	var mailer janitor.Mailer
	if cfg.SMTPHost != "" {
		mailer = &janitor.SMTPMailer{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		}
	} else {
		mailer = janitor.LogMailer{}
	}

	return janitor.NewSweeper(masClient, store, mailer, janitor.Config{
		LockAfterHours: cfg.LockAfterHours,
		ServerName:     cfg.ServerName,
		ExcludeMXIDs:   cfg.ExcludeMXIDs,
		DryRun:         cfg.DryRun,
		OwnerEmail:     cfg.OwnerEmail,
	})
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
