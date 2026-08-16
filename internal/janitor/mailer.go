package janitor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"time"
)

// SMTPMailer sends the owner digest as plain text over a TLS-required SMTP connection.
// It negotiates STARTTLS explicitly and fails closed if the server does not advertise STARTTLS
// or if the TLS handshake fails — it never authenticates or sends in plaintext. Authentication
// uses smtp.PlainAuth only after a successful STARTTLS upgrade. The request context is applied
// as a connection deadline via net.DialTimeout; SMTPTimeoutSec (default 30) caps the overall
// dial timeout. Certificate verification requires a working CA trust store in the runtime
// environment — see the Dockerfile's ca-certificates note (scratch has none by default).
type SMTPMailer struct {
	Host, Port, Username, Password, From string
	TimeoutSec                            int
	// tlsConfig, when non-nil, overrides the default TLS config used for STARTTLS.
	// Production code leaves this nil; tests use it to skip certificate verification
	// for self-signed test certificates.
	tlsConfig *tls.Config
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	timeout := time.Duration(m.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	addr := net.JoinHostPort(m.Host, m.Port)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}

	client, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer client.Close()

	if err := client.Hello("telecrypt.io"); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("smtp: server does not advertise STARTTLS — refusing to send in plaintext")
	}

	tlsCfg := m.tlsConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: m.Host}
	}
	if err := client.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}

	auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}

	if err := client.Mail(m.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", m.From, to, subject, body)
	if _, err := wc.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close body: %w", err)
	}

	return client.Quit()
}

// LogMailer is the degraded-but-not-fatal fallback used when no SMTP env vars are configured: it
// logs the digest instead of sending it. Contract: Sweeper treats a LogMailer.Send call as a
// successful delivery for high-water-mark purposes (see sweepDigest) — the same accounts won't be
// re-logged on the next sweep. That means if SMTP was meant to be configured and simply isn't
// (misconfiguration, not a deliberate choice), those sign-ups never reach a real inbox and only
// ever appear in this log line. Operators relying on the digest for review must either configure
// SMTP or watch these log lines directly.
type LogMailer struct{}

func (LogMailer) Send(ctx context.Context, to, subject, body string) error {
	slog.Info("janitor: SMTP not configured, logging digest instead of sending",
		"to", to, "subject", subject, "body", body)
	return nil
}
