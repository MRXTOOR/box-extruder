package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/box-extruder/dast/internal/auth/discovery"
	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/review"
	"github.com/box-extruder/dast/internal/runner"
	"github.com/box-extruder/dast/internal/storage"
)

// Server minimal REST API over filesystem job store.
type Server struct {
	WorkDir string
}

// NewServer creates API server.
func NewServer(workDir string) *Server {
	return &Server{WorkDir: workDir}
}

// Mount registers routes on mux (Go 1.22+ patterns).
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/discover", s.handleAuthDiscover)
	mux.HandleFunc("POST /api/v1/jobs", s.handleCreateJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/start", s.handleStartJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/jobs/{id}/reports", s.handleReports)
	mux.HandleFunc("PATCH /api/v1/jobs/{id}/findings/{findingId}", s.handleReviewFinding)
}

func (s *Server) handleAuthDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req discovery.Request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := discovery.Discover(req)
	w.Header().Set("Content-Type", "application/json")
	if !res.Verified && res.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleReviewFinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := r.PathValue("id")
	findingID := r.PathValue("findingId")
	if jobID == "" || findingID == "" {
		http.Error(w, "missing job or finding id", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		Action string `json:"action"`
		Note   string `json:"note"`
		Actor  string `json:"actor"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	act, err := review.ParseAction(req.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := review.Apply(s.WorkDir, jobID, findingID, act, req.Note, req.Actor); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg, err := config.ParseScanAsCode(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jobID, err := runner.CreateQueued(runner.Options{WorkDir: s.WorkDir, ConfigYAML: body, Config: cfg})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jobId":      jobID,
		"status":     "QUEUED",
		"configHash": storage.ConfigHashSHA256(body),
	})
}

func (s *Server) handleStartJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	if jobID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	skipZAP := r.URL.Query().Get("skipZap") == "1"
	if err := runner.Execute(s.WorkDir, jobID, skipZAP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	j, _ := storage.ReadJob(s.WorkDir, jobID)
	st := "SUCCEEDED"
	if j != nil {
		st = string(j.Status)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobId": jobID, "status": st})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	j, err := storage.ReadJob(s.WorkDir, jobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(j)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	j, err := storage.ReadJob(s.WorkDir, jobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobId": j.JobID, "status": j.Status, "steps": j.Steps, "error": j.Error})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	data, err := os.ReadFile(filepath.Join(storage.JobRoot(s.WorkDir, jobID), "events", "events.jsonl"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	format := r.URL.Query().Get("format")
	if strings.EqualFold(format, "docx") {
		root := filepath.Join(storage.JobRoot(s.WorkDir, jobID), "reports")
		p := filepath.Join(root, "report.docx")
		if _, err := os.Stat(p); err == nil {
			http.ServeFile(w, r, p)
			return
		}
		hp := filepath.Join(root, "report.html")
		if _, err := os.Stat(hp); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, hp)
			return
		}
		http.Error(w, "docx not available (install pandoc); html fallback missing", http.StatusNotFound)
		return
	}
	// default: markdown
	p := filepath.Join(storage.JobRoot(s.WorkDir, jobID), "reports", "report.md")
	http.ServeFile(w, r, p)
}
