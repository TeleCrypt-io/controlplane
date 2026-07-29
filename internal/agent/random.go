package agent

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
)

// randomLocalpart returns a lowercase-hex string safe as a Matrix username localpart
// (MAS's username_valid() accepts lowercase ascii/digits and a few symbols; hex is always valid).
func randomLocalpart() (string, error) {
	b := make([]byte, 10) // 20 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomPassword returns a high-entropy password. It's used once to drive MAS's public
// registration form and the compat login that follows, then discarded — never stored or handed
// to the agent; only the minted access_token/device_id are.
func randomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(b), nil
}

// randomDeviceID returns a Matrix-safe device ID for the agent's single, stable device.
func randomDeviceID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "AGT" + hex.EncodeToString(b), nil
}
