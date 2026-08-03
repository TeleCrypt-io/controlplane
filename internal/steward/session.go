package steward

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookieName = "tc_plan_session"
	oauthStateCookie  = "tc_plan_oauth_state"
	oauthPKCECookie   = "tc_plan_oauth_pkce"
)

var errUnauthorized = errors.New("unauthorized")

// Session holds Plan's browser-session signing key. It is deliberately Plan-owned rather than
// shared with Cashier: Cashier receives a separate short-lived internal assertion in the later
// transport implementation.
type Session struct{ key []byte }

func NewSession(key string) *Session { return &Session{key: []byte(key)} }

func (s *Session) Set(w http.ResponseWriter, mxid string) {
	exp := time.Now().Add(7 * 24 * time.Hour)
	payload := fmt.Sprintf("%s|%d", mxid, exp.Unix())
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + s.sign(payload)))
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: int((7 * 24 * time.Hour).Seconds())})
}

func (s *Session) MXID(r *http.Request) (string, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", errUnauthorized
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", errUnauthorized
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || !hmac.Equal([]byte(parts[2]), []byte(s.sign(parts[0]+"|"+parts[1]))) {
		return "", errUnauthorized
	}
	var exp int64
	if _, err := fmt.Sscan(parts[1], &exp); err != nil || time.Now().Unix() > exp {
		return "", errUnauthorized
	}
	return parts[0], nil
}

func (s *Session) sign(payload string) string {
	m := hmac.New(sha256.New, s.key)
	_, _ = m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func setOAuthCookies(w http.ResponseWriter, state, verifier string) {
	for _, spec := range []struct{ name, value string }{{oauthStateCookie, state}, {oauthPKCECookie, verifier}} {
		http.SetCookie(w, &http.Cookie{Name: spec.name, Value: spec.value, Path: "/plan", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	}
}

func readOAuthCookie(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", errUnauthorized
	}
	return c.Value, nil
}

func clearOAuthCookies(w http.ResponseWriter) {
	for _, name := range []string{oauthStateCookie, oauthPKCECookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/plan", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}
