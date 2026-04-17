package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/box-extruder/dast/internal/enterprise/auth"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/enterprise/queue"
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

	scan, err := db.GetScanByJobID(r.Context(), h.pool, jobID)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.UserID != c.UserID && c.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
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

	scan, err := db.GetScanByJobID(r.Context(), h.pool, jobID)
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

	scan, err := db.GetScanByJobID(r.Context(), h.pool, jobID)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.UserID != c.UserID && c.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": scan.Status,
	})
}

func (h *Handler) handleReports(w http.ResponseWriter, r *http.Request) {
	jobID := extractJobID(r.URL.Path)
	reportPath := fmt.Sprintf("%s/jobs/%s/reports/report.md", h.workDir, jobID)

	data, err := readFile(reportPath)
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/markdown")
	w.Write(data)
}

func (h *Handler) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	jobID := extractJobID(r.URL.Path)
	endpointsPath := fmt.Sprintf("%s/jobs/%s/contexts/contexts.jsonl", h.workDir, jobID)

	data, err := readFile(endpointsPath)
	if err != nil {
		http.Error(w, "endpoints not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
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

	scan, err := db.GetScanByJobID(r.Context(), h.pool, jobID)
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

	scan, err := db.GetScanByJobID(r.Context(), h.pool, jobID)
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

func readFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
