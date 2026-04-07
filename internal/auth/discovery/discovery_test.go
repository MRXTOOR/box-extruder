package discovery

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscover_JSONTokenFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"token123"}`))
		case "/api/me":
			if r.Header.Get("Authorization") == "Bearer token123" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	res := Discover(Request{
		TargetURL: srv.URL,
		Login:     "u@x",
		Password:  "p",
	})
	if !res.Verified {
		t.Fatalf("expected verified, got error=%s trace=%v", res.Error, res.Trace)
	}
	if res.GenericLogin == nil || res.GenericLogin.VerifyURL == "" {
		t.Fatalf("expected genericLogin config")
	}
}

func TestDiscover_CookieFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
			w.WriteHeader(http.StatusOK)
		case "/api/me":
			if r.Header.Get("Cookie") == "sid=abc" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	res := Discover(Request{
		TargetURL: srv.URL,
		Login:     "u@x",
		Password:  "p",
	})
	if !res.Verified {
		t.Fatalf("expected verified cookie flow, got error=%s", res.Error)
	}
	if res.GenericLogin == nil || !res.GenericLogin.UseCookies {
		t.Fatalf("expected useCookies=true")
	}
}

