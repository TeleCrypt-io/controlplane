package masreg

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func runRegistration(t *testing.T, baseURL string) error {
	t.Helper()
	_, err := NewClient(baseURL).RegisterAndAuthorizeDevice(
		context.Background(), "alice", "generated-password", "DEVICE-12345", baseURL,
	)
	return err
}

func TestRegisterAndAuthorizeDeviceMAS123Contract(t *testing.T) {
	var requests []string
	var mas *httptest.Server
	mas = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/register":
			http.Redirect(w, r, "/register/password", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/register/password":
			_, _ = w.Write([]byte(`<input name="csrf" value="register-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/register/password":
			if err := r.ParseForm(); err != nil {
				t.Errorf("password form: %v", err)
			}
			for field, want := range map[string]string{
				"csrf":             "register-csrf",
				"username":         "alice",
				"password":         "generated-password",
				"password_confirm": "generated-password",
				"accept_terms":     "on",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("password form %s = %q, want %q", field, got, want)
				}
			}
			http.Redirect(w, r, "/register/steps/account/display-name", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/register/steps/account/display-name":
			_, _ = w.Write([]byte(`<input name="csrf" value="display-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/register/steps/account/display-name":
			if err := r.ParseForm(); err != nil {
				t.Errorf("display-name form: %v", err)
			}
			if got, want := r.PostForm.Get("csrf"), "display-csrf"; got != want {
				t.Errorf("display-name csrf = %q, want %q", got, want)
			}
			if got, want := r.PostForm.Get("action"), "skip"; got != want {
				t.Errorf("display-name action = %q, want %q", got, want)
			}
			http.Redirect(w, r, "/register/steps/account/finish", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/register/steps/account/finish":
			http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/welcome":
			_, _ = w.Write([]byte("registration complete"))
		case r.Method == http.MethodPost && r.URL.Path == "/oauth2/registration":
			var body struct {
				ClientURI               string   `json:"client_uri"`
				RedirectURIs            []string `json:"redirect_uris"`
				ApplicationType         string   `json:"application_type"`
				TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
				GrantTypes              []string `json:"grant_types"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("dynamic registration body: %v", err)
			}
			if body.ClientURI != mas.URL || len(body.RedirectURIs) != 1 || body.RedirectURIs[0] != mas.URL {
				t.Errorf("dynamic registration URIs = %q, %q, want %q", body.ClientURI, body.RedirectURIs, mas.URL)
			}
			if body.ApplicationType != "native" || body.TokenEndpointAuthMethod != "none" {
				t.Errorf("dynamic registration client settings = %#v", body)
			}
			for _, want := range []string{
				"urn:ietf:params:oauth:grant-type:device_code",
				"refresh_token",
			} {
				if !slices.Contains(body.GrantTypes, want) {
					t.Errorf("dynamic registration grant_types = %q, missing %q", body.GrantTypes, want)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"client_id":"client-123"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/oauth2/device":
			if err := r.ParseForm(); err != nil {
				t.Errorf("device form: %v", err)
			}
			if got, want := r.PostForm.Get("client_id"), "client-123"; got != want {
				t.Errorf("device client_id = %q, want %q", got, want)
			}
			if !strings.Contains(r.PostForm.Get("scope"), "urn:matrix:org.matrix.msc2967.client:device:DEVICE-12345") {
				t.Errorf("device scope = %q, want device grant", r.PostForm.Get("scope"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_code":"device-123","user_code":"user-123","expires_in":60,"interval":1}`))
		case r.Method == http.MethodGet && r.URL.Path == "/link":
			if r.URL.RawQuery != "" {
				t.Errorf("device link GET query = %q, want no code auto-fill query", r.URL.RawQuery)
			}
			http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "link-csrf", Path: "/"})
			_, _ = w.Write([]byte(`<input name="csrf" value="link-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/link":
			if err := r.ParseForm(); err != nil {
				t.Errorf("device link form: %v", err)
			}
			for field, want := range map[string]string{
				"csrf": "link-csrf",
				"code": "user-123",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("device link %s = %q, want %q", field, got, want)
				}
			}
			http.Redirect(w, r, "/device/device-123", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/device/device-123":
			_, _ = w.Write([]byte(`<input name="csrf" value="consent-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/device/device-123":
			if err := r.ParseForm(); err != nil {
				t.Errorf("device consent form: %v", err)
			}
			for field, want := range map[string]string{
				"csrf":           "consent-csrf",
				"confirm_device": "on",
				"action":         "consent",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("device consent %s = %q, want %q", field, got, want)
				}
			}
			http.Redirect(w, r, "/device/complete", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/device/complete":
			_, _ = w.Write([]byte("device linked"))
		case r.Method == http.MethodPost && r.URL.Path == "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("token form: %v", err)
			}
			for field, want := range map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "device-123",
				"client_id":   "client-123",
			} {
				if got := r.PostForm.Get(field); got != want {
					t.Errorf("token form %s = %q, want %q", field, got, want)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-123","refresh_token":"refresh-123","expires_in":300}`))
		case r.Method == http.MethodGet && r.URL.Path == "/_matrix/client/v3/account/whoami":
			if got, want := r.Header.Get("Authorization"), "Bearer access-123"; got != want {
				t.Errorf("whoami authorization = %q, want %q", got, want)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"@alice:telecrypt.io","device_id":"DEVICE-12345"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mas.Close()

	got, err := NewClient(mas.URL).RegisterAndAuthorizeDevice(
		context.Background(), "alice", "generated-password", "DEVICE-12345", mas.URL,
	)
	if err != nil {
		t.Fatalf("RegisterAndAuthorizeDevice: %v", err)
	}
	if got.AccessToken != "access-123" || got.RefreshToken != "refresh-123" || got.ClientID != "client-123" {
		t.Fatalf("tokens = %#v, want MAS 1.23 device result", got)
	}
	if got.UserID != "@alice:telecrypt.io" || got.Issuer != mas.URL+"/" || got.TokenEndpoint != mas.URL+"/oauth2/token" {
		t.Fatalf("identity metadata = %#v, want MAS 1.23 identity", got)
	}
	for _, want := range []string{
		"GET /register",
		"GET /register/password",
		"POST /register/password",
		"GET /register/steps/account/display-name",
		"POST /register/steps/account/display-name",
		"GET /register/steps/account/finish",
		"POST /oauth2/registration",
		"POST /oauth2/device",
		"GET /link",
		"POST /link",
		"GET /device/device-123",
		"POST /device/device-123",
		"GET /device/complete",
		"POST /oauth2/token",
		"GET /_matrix/client/v3/account/whoami",
	} {
		if !slices.Contains(requests, want) {
			t.Errorf("request sequence is missing %q: %v", want, requests)
		}
	}
}

func TestApproveDeviceAuthorizationRejectsUnexpectedSameOriginLanding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/auth/link":
			_, _ = w.Write([]byte(`<input name="csrf" value="link-csrf">`))
		case r.Method == http.MethodPost && r.URL.Path == "/auth/link":
			http.Redirect(w, r, "/auth/unexpected", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/auth/unexpected":
			_, _ = w.Write([]byte(`<input name="csrf" value="unexpected-csrf">`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := &session{baseURL: srv.URL + "/auth", httpClient: &http.Client{}}
	err := s.approveDeviceAuthorization(context.Background(), "user-123")
	if err == nil || !strings.Contains(err.Error(), "did not redirect to consent") {
		t.Fatalf("approveDeviceAuthorization error = %v, want unexpected same-origin landing rejection", err)
	}
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

	whoamiTransport := &flakyTransport{body: `{"user_id":"@agent:telecrypt.io","device_id":"DEVICE-12345"}`}
	s.publicHTTPClient = &http.Client{Transport: whoamiTransport}
	userID, deviceID, err := s.whoAmI(context.Background(), "https://backend.example", "access")
	if err != nil || userID != "@agent:telecrypt.io" || deviceID != "DEVICE-12345" || whoamiTransport.calls != 2 {
		t.Fatalf("whoami result = %q, %q, %v, calls = %d", userID, deviceID, err, whoamiTransport.calls)
	}
}
