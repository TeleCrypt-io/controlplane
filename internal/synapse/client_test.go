package synapse

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
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
			name: "client transport timeout",
			err:  &CompatLoginError{Err: &url.Error{Op: "POST", URL: "https://mas/login", Err: context.DeadlineExceeded}},
			want: true,
		},
		{
			name: "rate limited",
			err:  &CompatLoginError{StatusCode: http.StatusTooManyRequests},
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

func TestCompatLoginPreservesRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).CompatLogin(context.Background(), "agent", "password", "DEVICE")
	if !IsRetryableCompatLogin(err) {
		t.Fatalf("CompatLogin error = %v, want retryable", err)
	}
	if got := CompatLoginRetryAfter(err); got != 2*time.Second {
		t.Fatalf("retry after = %v, want 2s", got)
	}
}

func TestCompatLoginTreatsTruncatedSuccessAsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user_id":`))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).CompatLogin(context.Background(), "agent", "password", "DEVICE")
	if !IsRetryableCompatLogin(err) {
		t.Fatalf("CompatLogin error = %v, want retryable", err)
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	got := parseRetryAfter(now.Add(3*time.Second).Format(http.TimeFormat), now)
	if got != 3*time.Second {
		t.Fatalf("retry after = %v, want 3s", got)
	}
}
