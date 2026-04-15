package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndStart_skipZap(t *testing.T) {
	dir := t.TempDir()
	yaml, err := os.ReadFile(filepath.Join("..", "runner", "testdata", "minimal-scan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	NewServer(dir).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/api/v1/jobs", "application/yaml", bytes.NewReader(yaml))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%v %d", err, resp.StatusCode)
	}
	var created struct {
		JobID string `json:"jobId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if created.JobID == "" {
		t.Fatal("empty jobId")
	}

	startURL := srv.URL + "/api/v1/jobs/" + created.JobID + "/start?skipZap=1"
	resp2, err := http.Post(startURL, "application/json", nil)
	if err != nil || resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("%v %d %s", err, resp2.StatusCode, body)
	}
	_ = resp2.Body.Close()

	stURL := srv.URL + "/api/v1/jobs/" + created.JobID + "/status"
	resp3, _ := http.Get(stURL)
	var st map[string]any
	_ = json.NewDecoder(resp3.Body).Decode(&st)
	_ = resp3.Body.Close()
	if st["status"] != "SUCCEEDED" && st["status"] != "PARTIAL_SUCCESS" {
		t.Fatalf("status: %v", st["status"])
	}
}

func TestAuthDiscoverEndpoint(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok123"}`))
		case "/api/me":
			if r.Header.Get("Authorization") == "Bearer tok123" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(app.Close)

	dir := t.TempDir()
	mux := http.NewServeMux()
	NewServer(dir).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	reqBody := map[string]any{
		"targetUrl": app.URL,
		"login":     "u@example.com",
		"password":  "secret",
	}
	b, _ := json.Marshal(reqBody)
	resp, err := http.Post(srv.URL+"/api/v1/auth/discover", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, d)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if v, _ := got["verified"].(bool); !v {
		t.Fatalf("expected verified=true, got %#v", got["verified"])
	}
}
