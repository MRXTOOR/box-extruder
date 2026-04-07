package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/storage"
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

func TestPatchReviewFinding(t *testing.T) {
	dir := t.TempDir()
	jobID := "job-patch-review"
	yamlBytes, err := os.ReadFile(filepath.Join("..", "runner", "testdata", "minimal-scan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.InitJobDirs(dir, jobID); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteConfigSnapshot(dir, jobID, yamlBytes, storage.ConfigHashSHA256(yamlBytes)); err != nil {
		t.Fatal(err)
	}
	j := &model.Job{JobID: jobID, CreatedAt: time.Now().UTC(), Status: model.JobSucceeded, ConfigHash: "x"}
	if err := storage.WriteJob(dir, j); err != nil {
		t.Fatal(err)
	}
	fid := "finding-1"
	now := time.Now().UTC()
	findings := []model.Finding{{
		FindingID: fid, RuleID: "r", Category: "c", Severity: model.SeverityHigh, Confidence: 0.5,
		LocationKey: "x", LifecycleStatus: model.LifecycleUnconfirmed,
		FirstSeenAt: now, LastSeenAt: now, Title: "t",
	}}
	if err := storage.WriteFindingsJSON(dir, jobID, "findings-final.json", findings); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	NewServer(dir).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	body := `{"action":"confirm","note":"via api","actor":"api"}`
	req, err := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/jobs/"+jobID+"/findings/"+fid, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("patch: %d %s", resp.StatusCode, b)
	}
	after, err := storage.LoadFindingsJSON(dir, jobID, "findings-final.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].LifecycleStatus != model.LifecycleConfirmed {
		t.Fatalf("finding: %+v", after[0])
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
