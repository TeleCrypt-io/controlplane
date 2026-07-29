package janitor

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
)

// SMTPMailer sends the owner digest as plain text via net/smtp: smtp.SendMail negotiates STARTTLS
// automatically when the server advertises the extension, then authenticates with PLAIN auth.
// Verifying the server's TLS certificate this way needs a working CA trust store in the runtime
// environment — see the Dockerfile's ca-certificates note (scratch has none by default).
type SMTPMailer struct {
	Host, Port, Username, Password, From string
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%s", m.Host, m.Port)
	auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", m.From, to, subject, body)

	if err := smtp.SendMail(addr, auth, m.From, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
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
