package synapse

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestIsRetryableCompatLogin(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "server error",
			err:  &CompatLoginError{StatusCode: http.StatusInternalServerError},
			want: true,
		},
		{
			name: "transport error",
			err:  &CompatLoginError{Err: &url.Error{Op: "POST", URL: "https://mas/login", Err: errors.New("reset")}},
			want: true,
		},
		{
			name: "authentication error",
			err:  &CompatLoginError{StatusCode: http.StatusUnauthorized},
			want: false,
		},
		{
			name: "context canceled",
			err:  &CompatLoginError{Err: context.Canceled},
			want: false,
		},
		{
			name: "untyped error",
			err:  errors.New("unknown"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryableCompatLogin(tt.err); got != tt.want {
				t.Fatalf("IsRetryableCompatLogin() = %v, want %v", got, tt.want)
			}
		})
	}
}
