package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/enterprise/auth"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/enterprise/queue"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req.Login = sanitizeInput(req.Login)

	if req.Login == "" || req.Password == "" {
		http.Error(w, "login and password required", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserByLogin(r.Context(), h.pool, req.Login)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := h.auth.GenerateToken(user.ID, user.Login, user.Role)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
		"user":  user.Login,
		"role":  user.Role,
	})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":    c.UserID,
		"login": c.Login,
		"role":  c.Role,
	})
}

func (h *Handler) handleListScans(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	scans, err := db.GetScansByUser(r.Context(), h.pool, c.UserID)
	if err != nil {
		log.Printf("ListScans error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func (h *Handler) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		TargetURL string `json:"targetUrl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req.TargetURL = sanitizeInput(req.TargetURL)

	if !isValidURL(req.TargetURL) {
		http.Error(w, "invalid target URL", http.StatusBadRequest)
		return
	}

	jobID := uuid.NewString()

	_, err := db.CreateScan(r.Context(), h.pool, c.UserID, jobID, req.TargetURL, "")
	if err != nil {
		log.Printf("CreateScan error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	job := queue.JobMessage{
		JobID:     jobID,
		UserID:    c.UserID,
		TargetURL: req.TargetURL,
	}

	if err := queue.Enqueue(r.Context(), h.rdb, job); err != nil {
		log.Printf("Enqueue error: %v", err)
		db.UpdateScanStatus(r.Context(), h.pool, jobID, "FAILED")
		http.Error(w, "failed to queue scan", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"id":        jobID,
		"targetUrl": req.TargetURL,
		"status":    "QUEUED",
	})
}

func (h *Handler) handleGetScan(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	jobID := extractJobID(r.URL.Path)

	scan, err := db.GetScanByID(r.Context(), h.pool, jobID)
	if err != nil {
		scan, err = db.GetScanByJobID(r.Context(), h.pool, jobID)
	}
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.UserID != c.UserID && c.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	findings, _ := db.GetFindingsByScanID(r.Context(), h.pool, scan.ID)
	if len(findings) == 0 {
		if fileFindings, err := storage.LoadFindingsJSON(h.workDir, scan.JobID, "findings-final.json"); err == nil {
			for _, f := range fileFindings {
				findings = append(findings, db.Finding{
					ID:          uuid.New().String(),
					ScanID:      scan.ID,
					Name:        f.Title,
					Severity:    string(f.Severity),
					Description: f.Description,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":        scan.ID,
		"jobId":     scan.JobID,
		"targetUrl":  scan.TargetURL,
		"status":     scan.Status,
		"createdAt":  scan.CreatedAt,
		"finishedAt":  scan.FinishedAt,
		"findings":   findings,
	})
}

func (h *Handler) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	jobID := extractJobID(r.URL.Path)

	scan, err := db.GetScanByID(r.Context(), h.pool, jobID)
	if err != nil {
		scan, err = db.GetScanByJobID(r.Context(), h.pool, jobID)
	}
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.UserID != c.UserID && c.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := db.DeleteScan(r.Context(), h.pool, jobID); err != nil {
		log.Printf("DeleteScan error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	jobID := extractJobID(r.URL.Path)
	log.Printf("handleScanStatus: jobID=%s, workDir=%s", jobID, h.workDir)

	scan, err := db.GetScanByID(r.Context(), h.pool, jobID)
	if err != nil {
		scan, err = db.GetScanByJobID(r.Context(), h.pool, jobID)
	}
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.UserID != c.UserID && c.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	j, readErr := storage.ReadJob(h.workDir, jobID)
	if readErr != nil {
		log.Printf("ERROR: ReadJob failed for %s: %v (workDir=%s)", jobID, readErr, h.workDir)
		j = nil
	} else {
		log.Printf("SUCCESS: ReadJob for %s returned job with startedAt=%v, finishedAt=%v, steps=%d", 
			jobID, j.StartedAt, j.FinishedAt, len(j.Steps))
	}

	var elapsedSeconds int64
	var progress int
	completedSteps, totalSteps := 0, 0
	if j != nil && j.StartedAt != nil && !j.StartedAt.IsZero() {
		end := time.Now()
		if j.FinishedAt != nil && !j.FinishedAt.IsZero() {
			end = *j.FinishedAt
		}
		elapsedSeconds = int64(end.Sub(*j.StartedAt).Seconds())

		totalSteps = len(j.Steps)
		for _, step := range j.Steps {
			if step.Status == "SUCCEEDED" || step.Status == "FAILED" || step.Status == "SKIPPED" {
				completedSteps++
			}
		}
		if totalSteps > 0 {
			progress = (completedSteps * 100) / totalSteps
		}
	}

	w.Header().Set("Content-Type", "application/json")
	var steps []map[string]any
	if j != nil && j.Steps != nil {
		for _, s := range j.Steps {
			steps = append(steps, map[string]any{
				"stepType": string(s.StepType),
				"status":   string(s.Status),
				"error":    s.Error,
			})
		}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status":           scan.Status,
		"elapsedSeconds":   elapsedSeconds,
		"progress":         progress,
		"completedSteps":   completedSteps,
		"totalSteps":       totalSteps,
		"steps":            steps,
	})
}

func (h *Handler) handleReports(w http.ResponseWriter, r *http.Request) {
	jobID := extractJobID(r.URL.Path)
	format := r.URL.Query().Get("format")
	
	workDir := h.workDir
	reportsDir := filepath.Join(workDir, "jobs", jobID, "reports")
	
	switch strings.ToLower(format) {
	case "html":
		reportPath := filepath.Join(reportsDir, "report.html")
		data, err := os.ReadFile(reportPath)
		if err != nil {
			http.Error(w, "HTML report not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report-%s.html\"", jobID[:8]))
		w.Write(data)
		return
	case "docx":
		reportPath := filepath.Join(reportsDir, "report.docx")
		data, err := os.ReadFile(reportPath)
		if err != nil {
			htmlPath := filepath.Join(reportsDir, "report.html")
			data, err = os.ReadFile(htmlPath)
			if err != nil {
				http.Error(w, "DOCX report not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report-%s.docx\"", jobID[:8]))
			w.Write(data)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report-%s.docx\"", jobID[:8]))
		w.Write(data)
		return
	case "endpoints":
		endpointsPath := filepath.Join(reportsDir, "endpoints.txt")
		data, err := os.ReadFile(endpointsPath)
		if err != nil {
			if j, readErr := storage.ReadJob(h.workDir, jobID); readErr == nil && len(j.ScannedEndpoints) > 0 {
				data = []byte(strings.Join(j.ScannedEndpoints, "\n"))
			} else {
				http.Error(w, "endpoints not found", http.StatusNotFound)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"endpoints-%s.txt\"", jobID[:8]))
		w.Write(data)
		return
	default:
		reportPath := filepath.Join(reportsDir, "report.md")
		data, err := os.ReadFile(reportPath)
		if err != nil {
			http.Error(w, "report not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report-%s.md\"", jobID[:8]))
		w.Write(data)
		return
	}
}

func (h *Handler) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	jobID := extractJobID(r.URL.Path)
	contextsDir := fmt.Sprintf("%s/jobs/%s/contexts", h.workDir, jobID)

	files, err := os.ReadDir(contextsDir)
	if err != nil {
		http.Error(w, "endpoints not found", http.StatusNotFound)
		return
	}

	var lines []string
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "context-") {
			data, err := os.ReadFile(filepath.Join(contextsDir, f.Name()))
			if err != nil {
				continue
			}
			lines = append(lines, string(data))
		}
	}

	if len(lines) == 0 {
		// Try to load from endpoints.txt
		endpoints, err := storage.LoadEndpointsTxt(h.workDir, jobID)
		if err == nil && len(endpoints) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[" + strings.Join(endpoints, "\n") + "]"))
			return
		}
		http.Error(w, "endpoints not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("[" + strings.Join(lines, ",") + "]"))
}

func (h *Handler) handleAuthDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetURL string `json:"targetUrl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req.TargetURL = sanitizeInput(req.TargetURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"targetUrl": req.TargetURL,
		"forms":     []string{},
		"loginUrls": []string{},
	})
}

func (h *Handler) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	jobID := extractJobID(r.URL.Path)
	if jobID == "" {
		http.Error(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	scan, err := db.GetScanByID(r.Context(), h.pool, jobID)
	if err != nil {
		scan, err = db.GetScanByJobID(r.Context(), h.pool, jobID)
	}
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.UserID != c.UserID && c.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if scan.Status == "SUCCEEDED" || scan.Status == "FAILED" || scan.Status == "CANCELED" {
		http.Error(w, "cannot cancel scan with status "+scan.Status, http.StatusBadRequest)
		return
	}

	if err := queue.SetCancelFlag(r.Context(), h.rdb, jobID); err != nil {
		log.Printf("SetCancelFlag error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "CANCELED",
	})
}

func (h *Handler) handleRestartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := r.Context().Value("user")
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, ok := claims.(*auth.Claims)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	jobID := extractJobID(r.URL.Path)
	if jobID == "" {
		http.Error(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	scan, err := db.GetScanByID(r.Context(), h.pool, jobID)
	if err != nil {
		scan, err = db.GetScanByJobID(r.Context(), h.pool, jobID)
	}
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.UserID != c.UserID && c.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if scan.Status != "SUCCEEDED" && scan.Status != "FAILED" && scan.Status != "CANCELED" {
		http.Error(w, "can only restart scans with status SUCCEEDED, FAILED, or CANCELED", http.StatusBadRequest)
		return
	}

	newJobID := uuid.NewString()

	if err := db.UpdateScanStatus(r.Context(), h.pool, newJobID, "QUEUED"); err != nil {
		log.Printf("RestartScan update status error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	job := queue.JobMessage{
		JobID:     newJobID,
		UserID:    c.UserID,
		TargetURL: scan.TargetURL,
	}

	if err := queue.Enqueue(r.Context(), h.rdb, job); err != nil {
		log.Printf("RestartScan enqueue error: %v", err)
		db.UpdateScanStatus(r.Context(), h.pool, newJobID, "FAILED")
		http.Error(w, "failed to queue scan", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":        newJobID,
		"targetUrl": scan.TargetURL,
		"status":    "QUEUED",
	})
}

func extractJobID(path string) string {
	re := regexp.MustCompile(`/scans/([^/]+)`)
	matches := re.FindStringSubmatch(path)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func isValidURL(url string) bool {
	if len(url) == 0 || len(url) > 2048 {
		return false
	}
	matched, _ := regexp.MatchString(`^https?://`, url)
	return matched
}

func sanitizeInput(input string) string {
	input = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(input, "")
	return input
}
