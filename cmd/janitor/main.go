// Command janitor is TeleCrypt.io's one-shot maintenance process holding a standing MAS admin
// credential. Each invocation locks stale unclaimed agent accounts via MAS's admin API and emails
// the owner a digest of new human sign-ups awaiting review. DRY_RUN=1 logs every action it would
// take without doing it.
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
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.JanitorDBURL)
	if err != nil {
		slog.Error("db connect", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("migrate", "error", err)
		os.Exit(1)
	}
	store := db.NewStore(pool)
	if err := store.BindBillingEnvironment(ctx, cfg.BillingEnv, cfg.ServerName); err != nil {
		slog.Error("billing environment guard", "error", err)
		os.Exit(1)
	}

	sweeper := build(cfg, pool)

	if err := sweeper.Sweep(ctx); err != nil {
		slog.Error("sweep", "error", err)
		os.Exit(1)
	}
	slog.Info("janitor sweep complete", "dry_run", cfg.DryRun)
}

func build(cfg *config.LockerConfig, pool *pgxpool.Pool) *janitor.Sweeper {
	masClient := masadmin.NewClient(cfg.MASAdminURL, cfg.MASAdminClientID, cfg.MASAdminClientSecret)
	store := db.NewStore(pool)

	var mailer janitor.Mailer
	if cfg.SMTPHost != "" {
		mailer = &janitor.SMTPMailer{
			Host:     cfg.SMTPHost,
			Port:     janitorSMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		}
	} else {
		mailer = janitor.LogMailer{}
	}

	return janitor.NewSweeper(masClient, store, mailer, janitor.Config{
		ServerName: cfg.ServerName,
		DryRun:     cfg.DryRun,
		OwnerEmail: cfg.OwnerEmail,
	})
}

const janitorSMTPPort = "587"
