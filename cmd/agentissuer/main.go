// Command agentissuer runs the private MAS OAuth/admin boundary used by credential-free Redpill.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agentissuer"
	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

func main() {
	cfg, err := config.LoadAgentIssuer()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	admin := masadmin.NewClient(cfg.MASBaseURL, cfg.MASAdminClientID, cfg.MASAdminClientSecret)
	handler, err := agentissuer.New(admin, cfg.RedpillAssertionPublicKey, cfg.Homeserver, cfg.ServerName)
	if err != nil {
		slog.Error("startup", "error", err)
		os.Exit(1)
	}
	server := &http.Server{Addr: cfg.ListenAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server", "error", err)
			os.Exit(1)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		slog.Error("shutdown", "error", err)
	}
}
