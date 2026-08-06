// Package agentissuer is the private privileged half of Redpill provisioning.
package agentissuer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/masadmin"
)

const (
	audience               = "telecrypt-agent-issuer"
	requestIDHeader        = "X-TeleCrypt-Request-ID"
	maximumAssertionWindow = 5 * time.Minute
	maximumBodyBytes       = 1024
)

type masProvisioner interface {
	CreateUser(context.Context, string) (masadmin.CreatedUser, error)
	CreatePersonalSession(context.Context, string, string, string, *uint32) (masadmin.PersonalSession, error)
	DeactivateUser(context.Context, string) error
}

type Server struct {
	mas        masProvisioner
	publicKey  ed25519.PublicKey
	homeserver string
	serverName string
	mux        *http.ServeMux
	seenMu     sync.Mutex
	seen       map[string]time.Time
}

func New(mas masProvisioner, encodedPublicKey, homeserver, serverName string) (*Server, error) {
	key, err := base64.RawURLEncoding.DecodeString(encodedPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("REDPILL_ASSERTION_PUBLIC_KEY must be a raw URL-safe base64 Ed25519 public key")
	}
	if homeserver == "" || serverName == "" {
		return nil, fmt.Errorf("homeserver and server name are required")
	}
	s := &Server{mas: mas, publicKey: ed25519.PublicKey(key), homeserver: strings.TrimRight(homeserver, "/"), serverName: serverName, mux: http.NewServeMux(), seen: make(map[string]time.Time)}
	s.mux.Handle("POST /internal/v1/agents", s.requireAssertion(http.HandlerFunc(s.handleCreateAgent)))
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	localpart, err := randomHex(10)
	if err != nil {
		http.Error(w, "provisioning failed", http.StatusInternalServerError)
		return
	}
	deviceSuffix, err := randomHex(8)
	if err != nil {
		http.Error(w, "provisioning failed", http.StatusInternalServerError)
		return
	}
	deviceID := "AGT" + deviceSuffix

	user, err := s.mas.CreateUser(r.Context(), localpart)
	if err != nil {
		slog.Error("agent issuer: create passwordless user", "error", err)
		http.Error(w, "provisioning failed", http.StatusBadGateway)
		return
	}
	scope := "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:" + deviceID
	session, err := s.mas.CreatePersonalSession(r.Context(), user.ID, "TeleCrypt agent "+deviceID, scope, nil)
	if err != nil {
		cleanupErr := s.mas.DeactivateUser(r.Context(), user.ID)
		slog.Error("agent issuer: issue personal session", "error", err, "cleanup_error", cleanupErr)
		http.Error(w, "provisioning failed", http.StatusBadGateway)
		return
	}
	result := agent.Provisioned{MXID: "@" + localpart + ":" + s.serverName, AccessToken: session.AccessToken, DeviceID: deviceID, Homeserver: s.homeserver}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

type assertion struct {
	Audience   string `json:"aud"`
	Expires    int64  `json:"exp"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	RequestID  string `json:"request_id"`
	BodySHA256 string `json:"body_sha256"`
}

func (s *Server) requireAssertion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maximumBodyBytes))
		if err != nil {
			http.Error(w, "invalid issuer request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		claims, err := verifyAssertion(r.Header.Get("Authorization"), s.publicKey)
		if err != nil || !s.acceptAssertion(claims, r.Method, r.URL.Path, r.Header.Get(requestIDHeader), body) {
			http.Error(w, "invalid issuer assertion", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// acceptAssertion consumes a valid request ID exactly once. Signatures are
// short-lived, but without this cache a captured private request could still
// be replayed during its validity window to mint additional agents.
func (s *Server) acceptAssertion(claims assertion, method, path, requestID string, body []byte) bool {
	if !validAssertion(claims, method, path, requestID, body) {
		return false
	}

	now := time.Now()
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	for id, expires := range s.seen {
		if !expires.After(now) {
			delete(s.seen, id)
		}
	}
	if _, exists := s.seen[requestID]; exists {
		return false
	}
	s.seen[requestID] = time.Unix(claims.Expires, 0)
	return true
}

func verifyAssertion(authorization string, key ed25519.PublicKey) (assertion, error) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return assertion{}, fmt.Errorf("missing bearer assertion")
	}
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(parts) != 3 {
		return assertion{}, fmt.Errorf("malformed assertion")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != `{"alg":"EdDSA","typ":"JWT"}` {
		return assertion{}, fmt.Errorf("invalid header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return assertion{}, fmt.Errorf("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return assertion{}, err
	}
	var claims assertion
	if err := json.Unmarshal(payload, &claims); err != nil {
		return assertion{}, err
	}
	return claims, nil
}

func validAssertion(claims assertion, method, path, requestID string, body []byte) bool {
	if claims.Audience != audience || claims.Method != method || claims.Path != path || claims.RequestID != requestID {
		return false
	}
	if _, err := uuid.Parse(requestID); err != nil {
		return false
	}
	expires, now := time.Unix(claims.Expires, 0), time.Now()
	if !expires.After(now) || expires.After(now.Add(maximumAssertionWindow)) {
		return false
	}
	sum := sha256.Sum256(body)
	return claims.BodySHA256 == base64.RawURLEncoding.EncodeToString(sum[:])
}
