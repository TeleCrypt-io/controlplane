package janitor

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server for testing STARTTLS-required behaviour.
// It can be configured to advertise STARTTLS (with a self-signed cert) or not.
type fakeSMTP struct {
	listener   net.Listener
	addr       string
	host       string
	startTLS   bool
	tlsConfig  *tls.Config
	gotMail    bool
	gotMessage string
}

func newFakeSMTP(t *testing.T, advertiseSTARTTLS bool) *fakeSMTP {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	f := &fakeSMTP{
		listener: listener,
		addr:     listener.Addr().String(),
		host:     host,
		port:     port,
		startTLS: advertiseSTARTTLS,
	}
	if advertiseSTARTTLS {
		f.tlsConfig = selfSignedTLSConfig(t, host)
	}
	go f.serve()
	return f
}

func (f *fakeSMTP) port() string {
	_, p, _ := net.SplitHostPort(f.addr)
	return p
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintf(conn, "220 fake.test ESMTP\r\n")
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO"):
			if f.startTLS {
				fmt.Fprintf(conn, "250-fake.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
			} else {
				fmt.Fprintf(conn, "250-fake.test\r\n250 AUTH PLAIN\r\n")
			}
		case strings.HasPrefix(cmd, "STARTTLS"):
			if !f.startTLS {
				fmt.Fprintf(conn, "502 Command not implemented\r\n")
				continue
			}
			fmt.Fprintf(conn, "220 Ready to start TLS\r\n")
			tlsConn := tls.Server(conn, f.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			br = bufio.NewReader(conn)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			f.gotMail = true
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT TO"):
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "DATA"):
			fmt.Fprintf(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
			var sb strings.Builder
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(line) == "." {
					break
				}
				sb.WriteString(line)
			}
			f.gotMessage = sb.String()
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "QUIT"):
			fmt.Fprintf(conn, "221 Bye\r\n")
			return
		default:
			fmt.Fprintf(conn, "502 Command not implemented\r\n")
		}
	}
}

func (f *fakeSMTP) close() {
	f.listener.Close()
}

func selfSignedTLSConfig(t *testing.T, host string) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func TestSMTPMailer_SendSucceedsWithSTARTTLS(t *testing.T) {
	srv := newFakeSMTP(t, true)
	defer srv.close()

	m := &SMTPMailer{
		Host:       srv.host,
		Port:       srv.port(),
		Username:   "user",
		Password:   "pass",
		From:       "from@test",
		TimeoutSec: 10,
		tlsConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: srv.host},
	}

	err := m.Send(context.Background(), "to@test", "Test", "body")
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if !srv.gotMail {
		t.Error("server did not receive MAIL FROM")
	}
	if !strings.Contains(srv.gotMessage, "body") {
		t.Errorf("server did not receive message body, got: %q", srv.gotMessage)
	}
}

func TestSMTPMailer_SendFailsWithoutSTARTTLS(t *testing.T) {
	srv := newFakeSMTP(t, false)
	defer srv.close()

	m := &SMTPMailer{
		Host:       srv.host,
		Port:       srv.port(),
		Username:   "user",
		Password:   "pass",
		From:       "from@test",
		TimeoutSec: 10,
		tlsConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: srv.host},
	}

	err := m.Send(context.Background(), "to@test", "Test", "body")
	if err == nil {
		t.Fatal("Send succeeded without STARTTLS — should have failed")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("expected STARTTLS-related error, got: %v", err)
	}
}