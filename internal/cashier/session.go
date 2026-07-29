package cashier

import (
	"context"
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

type sessionPayload struct {
	MXID      string
	ExpiresAt time.Time
}

type Session struct {
	key []byte
}

func NewSession(key string) *Session {
	return &Session{key: []byte(key)}
}

func (s *Session) Set(w http.ResponseWriter, mxid string) {
	exp := time.Now().Add(7 * 24 * time.Hour)
	payload := fmt.Sprintf("%s|%d", mxid, exp.Unix())
	sig := s.sign(payload)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
	})
}

func (s *Session) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})
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
	if len(parts) != 3 {
		return "", errUnauthorized
	}
	mxid, expStr, sig := parts[0], parts[1], parts[2]
	payload := mxid + "|" + expStr
	if !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return "", errUnauthorized
	}
	var expUnix int64
	if _, err := fmt.Sscan(expStr, &expUnix); err != nil {
		return "", errUnauthorized
	}
	if time.Now().Unix() > expUnix {
		return "", errUnauthorized
	}
	return mxid, nil
}

func (s *Session) sign(payload string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func setOAuthCookies(w http.ResponseWriter, state, verifier string) {
	for _, spec := range []struct {
		name, value string
	}{
		{oauthStateCookie, state},
		{oauthPKCECookie, verifier},
	} {
		http.SetCookie(w, &http.Cookie{
			Name:     spec.name,
			Value:    spec.value,
			Path:     "/plan",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600,
		})
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
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/plan", MaxAge: -1,
		})
	}
}

// noop context helper for interfaces
type ctxKey struct{}

func withMXID(ctx context.Context, mxid string) context.Context {
	return context.WithValue(ctx, ctxKey{}, mxid)
}

func mxidFromCtx(ctx context.Context) (string, bool) {
	mxid, ok := ctx.Value(ctxKey{}).(string)
	return mxid, ok
}
