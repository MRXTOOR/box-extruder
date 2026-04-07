package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

func TestEngine_noAuth(t *testing.T) {
	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: "https://x.example"}},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthAuthenticated {
		t.Fatal(res.Context.AuthVerification)
	}
}

func TestEngine_headerEndpointCheck_ok(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" && r.Header.Get("Authorization") == "Bearer ok" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("UNIT_BEARER", "Bearer ok")

	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type:       "header",
				ID:         "h1",
				SecretsRef: map[string]string{"headerValue": "secret://UNIT_BEARER"},
				Config:     map[string]string{"headerName": "Authorization"},
				Verification: &config.AuthVerification{
					Type:    "endpointCheck",
					Details: map[string]any{"url": srv.URL + "/me", "expectedStatus": 200},
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthAuthenticated {
		t.Fatalf("want Authenticated got %v", res.Context.AuthVerification)
	}
}

func TestEngine_headerEndpointCheck_fail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("UNIT_BEARER2", "Bearer x")

	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type:       "header",
				ID:         "h1",
				SecretsRef: map[string]string{"headerValue": "secret://UNIT_BEARER2"},
				Config:     map[string]string{"headerName": "Authorization"},
				Verification: &config.AuthVerification{
					Type:    "endpointCheck",
					Details: map[string]any{"url": srv.URL + "/me", "expectedStatus": 200},
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthNotAuthenticated {
		t.Fatalf("want NotAuthenticated got %v", res.Context.AuthVerification)
	}
}

func TestEngine_juiceShopLogin_ok(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/rest/user/login" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"authentication":{"token":"jwt-test-token","bid":1,"umail":"u@x"}}`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/rest/user/whoami" {
			if r.Header.Get("Authorization") == "Bearer jwt-test-token" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL + "/"}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "juiceShopLogin",
				ID:   "juice",
				SecretsRef: map[string]string{
					"email":    "jim@juice-sh.op",
					"password": "ncc-1701",
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthAuthenticated {
		t.Fatalf("want Authenticated got %v", res.Context.AuthVerification)
	}
	if res.HeaderInject["Authorization"] != "Bearer jwt-test-token" {
		t.Fatalf("unexpected Authorization: %q", res.HeaderInject["Authorization"])
	}
}

func TestEngine_juiceShopLogin_badPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/rest/user/login" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "juiceShopLogin",
				ID:   "juice",
				SecretsRef: map[string]string{
					"email":    "x",
					"password": "wrong",
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthNotAuthenticated {
		t.Fatalf("want NotAuthenticated got %v", res.Context.AuthVerification)
	}
}

func TestEngine_oidcClientCredentials_ok(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token_endpoint":"` + srv.URL + `/oauth/token"}`))
		case "/oauth/token":
			u, p, ok := r.BasicAuth()
			if !ok || u != "cid" || p != "csecret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"oidc-token","token_type":"Bearer"}`))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer oidc-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: "https://x.example"}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "oidcClientCredentials",
				ID:   "oidc",
				SecretsRef: map[string]string{
					"clientId":     "cid",
					"clientSecret": "csecret",
				},
				Config: map[string]string{
					"issuer": srv.URL,
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthAuthenticated {
		t.Fatalf("want Authenticated got %v", res.Context.AuthVerification)
	}
	if res.HeaderInject["Authorization"] != "Bearer oidc-token" {
		t.Fatalf("unexpected Authorization: %q", res.HeaderInject["Authorization"])
	}
}

func TestEngine_oidcClientCredentials_badSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.WriteHeader(http.StatusUnauthorized)
		case "/userinfo":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: "https://x.example"}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "oidcClientCredentials",
				ID:   "oidc",
				SecretsRef: map[string]string{
					"clientId":     "cid",
					"clientSecret": "wrong",
				},
				Config: map[string]string{
					"tokenEndpoint": srv.URL + "/oauth/token",
					"verifyUrl":     srv.URL + "/userinfo",
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthNotAuthenticated {
		t.Fatalf("want NotAuthenticated got %v", res.Context.AuthVerification)
	}
}

func TestEngine_genericLogin_json_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"token":"abc123"}}`))
			return
		}
		if r.URL.Path == "/api/me" && r.Header.Get("Authorization") == "Bearer abc123" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "genericLogin",
				ID:   "g1",
				SecretsRef: map[string]string{
					"email":    "u@x",
					"password": "p@ss",
				},
				GenericLogin: &config.GenericLoginConfig{
					LoginURL:     srv.URL + "/api/login",
					ContentType:  "application/json",
					CredentialFields: map[string]string{"email": "email", "password": "password"},
					TokenPath:    "data.token",
					VerifyURL:    srv.URL + "/api/me",
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthAuthenticated {
		t.Fatalf("want Authenticated got %v", res.Context.AuthVerification)
	}
	if res.HeaderInject["Authorization"] != "Bearer abc123" {
		t.Fatalf("unexpected auth header %q", res.HeaderInject["Authorization"])
	}
}

func TestEngine_genericLogin_form_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" && r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Form.Get("username") == "user1" && r.Form.Get("password") == "pass1" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"t1"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/userinfo" && r.Header.Get("Authorization") == "Bearer t1" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "genericLogin",
				ID:   "g2",
				SecretsRef: map[string]string{
					"username": "user1",
					"password": "pass1",
				},
				GenericLogin: &config.GenericLoginConfig{
					LoginURL:     srv.URL + "/auth",
					ContentType:  "application/x-www-form-urlencoded",
					CredentialFields: map[string]string{"username": "username", "password": "password"},
					VerifyURL:    srv.URL + "/userinfo",
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthAuthenticated {
		t.Fatalf("want Authenticated got %v", res.Context.AuthVerification)
	}
}

func TestEngine_genericLogin_cookie_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session/login" && r.Method == http.MethodPost {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s123", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if r.URL.Path == "/session/me" && strings.Contains(r.Header.Get("Cookie"), "sid=s123") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "genericLogin",
				ID:   "g3",
				SecretsRef: map[string]string{
					"login":    "u1",
					"password": "p1",
				},
				GenericLogin: &config.GenericLoginConfig{
					LoginURL:     srv.URL + "/session/login",
					ContentType:  "application/json",
					CredentialFields: map[string]string{"login": "login", "password": "password"},
					UseCookies:   true,
					VerifyURL:    srv.URL + "/session/me",
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthAuthenticated {
		t.Fatalf("want Authenticated got %v", res.Context.AuthVerification)
	}
	if !strings.Contains(res.HeaderInject["Cookie"], "sid=s123") {
		t.Fatalf("cookie not injected: %q", res.HeaderInject["Cookie"])
	}
}

func TestEngine_genericLogin_verify_fail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"bad-token"}`))
			return
		}
		if r.URL.Path == "/api/me" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	cfg := &config.ScanAsCode{
		Targets: []config.Target{{Type: "web", BaseURL: srv.URL}},
		Auth: &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "genericLogin",
				ID:   "g4",
				SecretsRef: map[string]string{
					"email":    "u@x",
					"password": "bad",
				},
				GenericLogin: &config.GenericLoginConfig{
					LoginURL:     srv.URL + "/api/login",
					ContentType:  "application/json",
					CredentialFields: map[string]string{"email": "email", "password": "password"},
					VerifyURL:    srv.URL + "/api/me",
				},
			}},
		},
	}
	config.MergeDefaults(cfg)
	res, err := NewEngine().Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Context.AuthVerification != model.AuthNotAuthenticated {
		t.Fatalf("want NotAuthenticated got %v", res.Context.AuthVerification)
	}
}
