package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/auth/discovery"
	"github.com/box-extruder/dast/internal/config"
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

	// jobs endpoints
	mux.HandleFunc("GET /api/v1/jobs", s.handleListJobs)
	mux.HandleFunc("POST /api/v1/jobs", s.handleCreateJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/start", s.handleStartJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("DELETE /api/v1/jobs/{id}", s.handleDeleteJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/jobs/{id}/reports", s.handleReports)
	mux.HandleFunc("GET /api/v1/jobs/{id}/endpoints", s.handleEndpoints)

	// scans endpoints (alias for jobs)
	mux.HandleFunc("GET /api/v1/scans", s.handleListJobs)
	mux.HandleFunc("POST /api/v1/scans", s.handleCreateJob)
	mux.HandleFunc("POST /api/v1/scans/{id}/start", s.handleStartJob)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleGetJob)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", s.handleDeleteJob)
	mux.HandleFunc("GET /api/v1/scans/{id}/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/scans/{id}/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/scans/{id}/reports", s.handleReports)
	mux.HandleFunc("GET /api/v1/scans/{id}/endpoints", s.handleEndpoints)
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", s.handleCancel)
	mux.HandleFunc("POST /api/v1/scans/{id}/restart", s.handleRestart)
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

func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := r.PathValue("id")
	if jobID == "" {
		http.Error(w, "missing job id", http.StatusBadRequest)
		return
	}
	if err := storage.DeleteJob(s.WorkDir, jobID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "deleted": jobID})
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobs, err := storage.ListJobs(s.WorkDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	j, err := storage.ReadJob(s.WorkDir, jobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var elapsedSeconds int64
	if j.StartedAt != nil && !j.StartedAt.IsZero() {
		end := time.Now()
		if j.FinishedAt != nil && !j.FinishedAt.IsZero() {
			end = *j.FinishedAt
		}
		elapsedSeconds = int64(end.Sub(*j.StartedAt).Seconds())
	}

	totalSteps := len(j.Steps)
	var completedSteps int
	for _, step := range j.Steps {
		if step.Status == "SUCCEEDED" || step.Status == "FAILED" || step.Status == "SKIPPED" {
			completedSteps++
		}
	}
	progress := 0
	if totalSteps > 0 {
		progress = (completedSteps * 100) / totalSteps
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jobId":           j.JobID,
		"status":          j.Status,
		"steps":          j.Steps,
		"error":          j.Error,
		"elapsedSeconds": elapsedSeconds,
		"progress":       progress,
		"completedSteps": completedSteps,
		"totalSteps":     totalSteps,
	})
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

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	format := r.URL.Query().Get("format")
	j, err := storage.ReadJob(s.WorkDir, jobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	endpoints := j.ScannedEndpoints
	if len(endpoints) == 0 {
		http.Error(w, "no endpoints found for this job", http.StatusNotFound)
		return
	}
	if strings.EqualFold(format, "txt") || strings.EqualFold(format, "text") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"endpoints-%s.txt\"", jobID))
		for _, ep := range endpoints {
			fmt.Fprintf(w, "%s\n", ep)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"endpoints": endpoints, "count": len(endpoints)})
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	format := r.URL.Query().Get("format")
	root := filepath.Join(storage.JobRoot(s.WorkDir, jobID), "reports")
	if strings.EqualFold(format, "docx") || strings.EqualFold(format, "word") {
		p := filepath.Join(root, "report.docx")
		if _, err := os.Stat(p); err == nil {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"DAST-Report-%s.docx\"", jobID))
			http.ServeFile(w, r, p)
			return
		}
		hp := filepath.Join(root, "report.html")
		if _, err := os.Stat(hp); err == nil {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"DAST-Report-%s.html\"", jobID))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, hp)
			return
		}
		http.Error(w, "docx not available (install pandoc); html fallback missing", http.StatusNotFound)
		return
	}
	if strings.EqualFold(format, "html") {
		p := filepath.Join(root, "report.html")
		if _, err := os.Stat(p); err == nil {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"DAST-Report-%s.html\"", jobID))
			http.ServeFile(w, r, p)
			return
		}
		http.Error(w, "html report not found", http.StatusNotFound)
		return
	}
	if strings.EqualFold(format, "json") {
		findings, err := storage.LoadFindingsJSON(s.WorkDir, jobID, "findings-final.json")
		if err != nil {
			findings, _ = storage.LoadFindingsJSON(s.WorkDir, jobID, "findings-raw.json")
		}
		evidence, _ := storage.LoadEvidenceDir(s.WorkDir, jobID)
		j, _ := storage.ReadJob(s.WorkDir, jobID)
		resp := map[string]any{
			"job":      j,
			"findings": findings,
			"evidence": evidence,
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"DAST-Report-%s.json\"", jobID))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	// default: markdown
	p := filepath.Join(root, "report.md")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"DAST-Report-%s.md\"", jobID))
	http.ServeFile(w, r, p)
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := r.PathValue("id")
	if jobID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	j, err := storage.ReadJob(s.WorkDir, jobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	j.Status = "CANCELLED"
	_ = storage.WriteJob(s.WorkDir, j)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobId": jobID, "status": j.Status})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := r.PathValue("id")
	if jobID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	j, err := storage.ReadJob(s.WorkDir, jobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	initialStatus := j.Status
	j.Status = "QUEUED"
	for i := range j.Steps {
		j.Steps[i].Status = ""
		j.Steps[i].Error = ""
	}
	_ = storage.WriteJob(s.WorkDir, j)

if err := runner.Execute(s.WorkDir, jobID, false); err != nil {
		j.Status = initialStatus
		_ = storage.WriteJob(s.WorkDir, j)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	j, _ = storage.ReadJob(s.WorkDir, jobID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobId": jobID, "status": j.Status, "steps": j.Steps})
}
