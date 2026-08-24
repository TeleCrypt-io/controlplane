package jsonbody

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeAcceptsOneValueAndWhitespace(t *testing.T) {
	var got map[string]string
	if err := Decode(strings.NewReader("{\"token\":\"ok\"} \n\t"), 64, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got["token"] != "ok" {
		t.Fatalf("decoded value = %#v", got)
	}
}

func TestDecodeRejectsTrailingJSONAndData(t *testing.T) {
	for _, body := range []string{`{"a":1}{"b":2}`, `{"a":1} trailing`} {
		var got map[string]int
		err := Decode(strings.NewReader(body), 64, &got)
		if !errors.Is(err, ErrTrailingData) {
			t.Errorf("Decode(%q) = %v, want trailing-data error", body, err)
		}
	}
}

func TestDecodeRejectsMaxPlusOne(t *testing.T) {
	var got map[string]string
	err := Decode(strings.NewReader(`{"token":"123456789"}`), 10, &got)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("Decode oversized = %v, want body-too-large error", err)
	}
}
