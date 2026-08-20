package masreg

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func runRegistration(t *testing.T, baseURL string) error {
	t.Helper()
	_, err := NewClient(baseURL).RegisterAndAuthorizeDevice(
		context.Background(), "alice", "generated-password", "DEVICE", baseURL,
	)
	return err
}

func TestRegisterAndAuthorizeDeviceRejectsOffOriginRedirect(t *testing.T) {
	var offOriginRequests int
	offOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offOriginRequests++
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer offOrigin.Close()

	mas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			t.Errorf("MAS received unexpected path %q", r.URL.Path)
		}
		http.Redirect(w, r, offOrigin.URL+"/register/password", http.StatusSeeOther)
	}))
	defer mas.Close()

	err := runRegistration(t, mas.URL)
	if err == nil || !strings.Contains(err.Error(), "redirected outside its configured origin") {
		t.Fatalf("registration error = %v, want off-origin redirect rejection", err)
	}
	if offOriginRequests != 0 {
		t.Fatalf("off-origin server received %d requests; redirect must be rejected before credentials leave MAS", offOriginRequests)
	}
}

func TestRegisterAndAuthorizeDeviceRejectsProviderChoicePage(t *testing.T) {
	var passwordPosts int
	mas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/register" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<input name="csrf" value="csrf">`))
		case r.Method == http.MethodPost:
			passwordPosts++
			http.Error(w, "unexpected password submission", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mas.Close()

	err := runRegistration(t, mas.URL)
	if err == nil || !strings.Contains(err.Error(), "/register/password") {
		t.Fatalf("registration error = %v, want provider-choice rejection", err)
	}
	if passwordPosts != 0 {
		t.Fatalf("password form received %d submissions after provider-choice page", passwordPosts)
	}
}

func TestRegisterAndAuthorizeDeviceRejectsIncompleteRegistrationAtBasePath(t *testing.T) {
	const prefix = "/auth"
	mas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case prefix + "/register":
			if r.Method != http.MethodGet {
				t.Errorf("register request method = %s, want GET", r.Method)
			}
			http.Redirect(w, r, prefix+"/register/password", http.StatusSeeOther)
		case prefix + "/register/password":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<input name="csrf" value="csrf">`))
				return
			}
			http.Redirect(w, r, prefix+"/register/steps/one/display-name", http.StatusSeeOther)
		case prefix + "/register/steps/one/display-name":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<input name="csrf" value="csrf">`))
				return
			}
			http.Redirect(w, r, prefix+"/register/steps/one/finish", http.StatusSeeOther)
		case prefix + "/register/steps/one/finish":
			_, _ = w.Write([]byte("still incomplete"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mas.Close()

	err := runRegistration(t, mas.URL+prefix)
	if err == nil || !strings.Contains(err.Error(), "registration did not complete") {
		t.Fatalf("registration error = %v, want incomplete registration rejection", err)
	}
}

func TestOAuthRetriesHonorCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &session{baseURL: "http://127.0.0.1:1"}
	device := &deviceAuthorization{DeviceCode: "code", ExpiresIn: 60, Interval: 1}
	if _, err := s.pollDeviceToken(ctx, "client", device); !errors.Is(err, context.Canceled) {
		t.Fatalf("poll error = %v, want context canceled", err)
	}
	if _, _, err := s.whoAmI(ctx, "http://127.0.0.1:1", "token"); !errors.Is(err, context.Canceled) {
		t.Fatalf("whoami error = %v, want context canceled", err)
	}
}

type flakyTransport struct {
	calls int
	body  string
}

func (t *flakyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	if t.calls == 1 {
		return nil, errors.New("temporary connection reset")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.body)),
	}, nil
}

func TestOAuthRetriesTransientTransportErrors(t *testing.T) {
	tokenTransport := &flakyTransport{body: `{"access_token":"access","refresh_token":"refresh","expires_in":60}`}
	s := &session{baseURL: "https://mas.example", publicHTTPClient: &http.Client{Transport: tokenTransport}}
	got, err := s.pollDeviceToken(context.Background(), "client", &deviceAuthorization{DeviceCode: "code", ExpiresIn: 60})
	if err != nil || got.AccessToken != "access" || tokenTransport.calls != 2 {
		t.Fatalf("poll result = %#v, err = %v, calls = %d", got, err, tokenTransport.calls)
	}

	whoamiTransport := &flakyTransport{body: `{"user_id":"@agent:telecrypt.io","device_id":"DEVICE"}`}
	s.publicHTTPClient = &http.Client{Transport: whoamiTransport}
	userID, deviceID, err := s.whoAmI(context.Background(), "https://backend.example", "access")
	if err != nil || userID != "@agent:telecrypt.io" || deviceID != "DEVICE" || whoamiTransport.calls != 2 {
		t.Fatalf("whoami result = %q, %q, %v, calls = %d", userID, deviceID, err, whoamiTransport.calls)
	}
}
