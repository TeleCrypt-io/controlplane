// Package jsonbody decodes one bounded JSON value from an upstream response.
package jsonbody

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrBodyTooLarge means the response exceeded the caller's byte limit.
	ErrBodyTooLarge = errors.New("JSON body too large")
	// ErrTrailingData means the response contained more than one JSON value or
	// non-whitespace data after the first value.
	ErrTrailingData = errors.New("JSON body contains trailing data")
)

// Decode reads at most maxBytes+1 bytes, decodes exactly one JSON value into
// dst, and rejects both oversized responses and any trailing JSON or data.
func Decode(r io.Reader, maxBytes int, dst any) error {
	if maxBytes < 1 {
		return fmt.Errorf("invalid JSON body limit %d", maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return fmt.Errorf("read JSON body: %w", err)
	}
	if len(body) > maxBytes {
		return ErrBodyTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ErrTrailingData
		}
		return fmt.Errorf("%w: %v", ErrTrailingData, err)
	}
	return nil
}
