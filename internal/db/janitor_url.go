package db

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var janitorDatabaseURLQueryAllowlist = map[string]struct{}{
	"sslmode":          {},
	"connect_timeout":  {},
	"application_name": {},
}

// ValidateJanitorDatabaseURL rejects URL forms that could make pgx read local files, select a
// different connection target, or alter Janitor's session before its private-schema pin applies.
// The authority supplies host, port, user, password, and database; only the small allowlist of
// non-file connection options may appear in the query.
func ValidateJanitorDatabaseURL(databaseURL string) error {
	if databaseURL == "" || strings.TrimSpace(databaseURL) != databaseURL {
		return fmt.Errorf("JANITOR_DB_URL must be a non-empty, whitespace-free Postgres URL")
	}
	if !strings.HasPrefix(databaseURL, "postgres://") && !strings.HasPrefix(databaseURL, "postgresql://") {
		return fmt.Errorf("JANITOR_DB_URL must be an explicit Postgres URL")
	}
	u, err := url.Parse(databaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" ||
		u.User == nil || u.Path == "" || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || u.ForceQuery || strings.Contains(databaseURL, "#") {
		return fmt.Errorf("JANITOR_DB_URL must be an explicit Postgres URL")
	}
	if err := validateJanitorAuthority(databaseURL, u); err != nil {
		return err
	}
	database := strings.TrimPrefix(u.Path, "/")
	if !canonicalJanitorIdentifier(database) {
		return fmt.Errorf("JANITOR_DB_URL must use a canonical database path")
	}
	if err := validateJanitorDatabaseURLQuery(u.RawQuery); err != nil {
		return err
	}
	return nil
}

func validateJanitorAuthority(raw string, u *url.URL) error {
	if strings.TrimSpace(u.Host) != u.Host || strings.Contains(u.Host, ",") ||
		strings.IndexFunc(u.Host, unicode.IsSpace) >= 0 {
		return fmt.Errorf("JANITOR_DB_URL must use one canonical non-whitespace authority")
	}
	hostname := u.Hostname()
	if hostname == "" || strings.Contains(hostname, "%") || strings.Contains(hostname, ":") && !strings.HasPrefix(u.Host, "[") || hostname != strings.ToLower(hostname) || strings.HasSuffix(hostname, ".") || strings.Contains(hostname, "..") {
		return fmt.Errorf("JANITOR_DB_URL must use a canonical database host")
	}
	if strings.HasPrefix(u.Host, "[") && !strings.Contains(hostname, ":") {
		return fmt.Errorf("JANITOR_DB_URL must use a canonical database host")
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") || port != "" {
		if port == "" || (len(port) > 1 && port[0] == '0') {
			return fmt.Errorf("JANITOR_DB_URL must use a canonical database port")
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("JANITOR_DB_URL must use a canonical database port")
		}
	}
	if u.User == nil || u.User.Username() == "" || !canonicalJanitorIdentifier(u.User.Username()) {
		return fmt.Errorf("JANITOR_DB_URL must use a canonical database user")
	}
	password, hasPassword := u.User.Password()
	if !hasPassword || password == "" || containsJanitorWhitespaceOrControl(password) {
		return fmt.Errorf("JANITOR_DB_URL must use an explicit non-whitespace database password")
	}
	userinfoStart := strings.Index(raw, "://") + 3
	userinfoEnd := strings.IndexAny(raw[userinfoStart:], "/?#")
	if userinfoEnd < 0 {
		userinfoEnd = len(raw) - userinfoStart
	}
	rawAuthority := raw[userinfoStart : userinfoStart+userinfoEnd]
	at := strings.LastIndexByte(rawAuthority, '@')
	if at < 0 {
		return fmt.Errorf("JANITOR_DB_URL must use an explicit database user")
	}
	if strings.Contains(rawAuthority[:at], "@") {
		return fmt.Errorf("JANITOR_DB_URL must use a canonical database authority")
	}
	rawUser := rawAuthority[:at]
	if colon := strings.IndexByte(rawUser, ':'); colon >= 0 {
		rawUser = rawUser[:colon]
	}
	if rawUser != u.User.Username() {
		return fmt.Errorf("JANITOR_DB_URL must use an unencoded database user")
	}
	return nil
}

func canonicalJanitorIdentifier(value string) bool {
	if value == "" || value != strings.ToLower(value) || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}
	for i, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
		if i == 0 && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

func validateJanitorDatabaseURLQuery(rawQuery string) error {
	if rawQuery == "" {
		return nil
	}
	if _, err := url.ParseQuery(rawQuery); err != nil {
		return fmt.Errorf("JANITOR_DB_URL contains an invalid query")
	}
	seen := make(map[string]struct{})
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			return fmt.Errorf("JANITOR_DB_URL contains an empty query parameter")
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			return fmt.Errorf("JANITOR_DB_URL contains an invalid query parameter")
		}
		rawKey := part[:eq]
		key, err := url.QueryUnescape(rawKey)
		if err != nil || key != rawKey || strings.TrimSpace(key) != key {
			return fmt.Errorf("JANITOR_DB_URL query parameter %q is not allowed", rawKey)
		}
		if _, present := seen[key]; present {
			return fmt.Errorf("JANITOR_DB_URL query parameter %q must not be repeated", key)
		}
		seen[key] = struct{}{}
		if _, allowed := janitorDatabaseURLQueryAllowlist[key]; !allowed {
			return fmt.Errorf("JANITOR_DB_URL query parameter %q is not allowed", key)
		}
		value, err := url.QueryUnescape(part[eq+1:])
		if err != nil || value == "" || containsJanitorWhitespaceOrControl(value) {
			return fmt.Errorf("JANITOR_DB_URL query parameter %q must have one non-whitespace value", key)
		}
	}
	return nil
}

func containsJanitorWhitespaceOrControl(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0
}
