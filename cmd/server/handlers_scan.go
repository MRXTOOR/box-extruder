package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/enterprise/auth"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/enterprise/queue"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/box-extruder/dast/internal/webscan"
	"github.com/google/uuid"
)

func (h *Handler) handleListScans(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	scans, err := db.GetScansByUser(r.Context(), h.pool, c.UserID)
	if err != nil {
		log.Printf("ListScans error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

type createScanRequest struct {
	TargetURL             string `json:"targetUrl"`
	Login                 string `json:"login"`
	Password              string `json:"password"`
	AuthURL               string `json:"authUrl"`
	VerifyURL             string `json:"verifyUrl"`
	KatanaDepth           *int   `json:"katanaDepth"`
	KatanaMaxURLs         *int   `json:"katanaMaxUrls"`
	ZapSpiderMinutes      *int   `json:"zapSpiderMinutes"`
	ZapPassiveSecs        *int   `json:"zapPassiveSecs"`
	StartPoints           string `json:"startPoints"`
	InsecureSkipTLSVerify bool   `json:"insecureSkipVerify"`
}

func (h *Handler) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req, ok := decodeCreateScanRequest(w, r)
	if !ok {
		return
	}

	jobID := uuid.NewString()
	yamlBytes, err := buildCreateScanYAML(jobID, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfgHash := storage.ConfigHashSHA256(yamlBytes)

	if err := storage.InitJobDirs(h.workDir, jobID); err != nil {
		log.Printf("InitJobDirs error: %v", err)
		http.Error(w, "failed to prepare scan workspace", http.StatusInternalServerError)
		return
	}
	if err := storage.WriteConfigSnapshot(h.workDir, jobID, yamlBytes, cfgHash); err != nil {
		log.Printf("WriteConfigSnapshot error: %v", err)
		http.Error(w, "failed to save scan config", http.StatusInternalServerError)
		return
	}

	scanUserID, ciTokenID, source, err := h.resolveScanCreateMeta(r.Context(), c)
	if err != nil {
		log.Printf("resolveScanCreateMeta error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if _, err := db.CreateScanWithMeta(r.Context(), h.pool, db.CreateScanParams{
		UserID: scanUserID, JobID: jobID, TargetURL: req.TargetURL, ConfigHash: cfgHash,
		CITokenID: ciTokenID, Source: source,
	}); err != nil {
		log.Printf("CreateScan error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	job := queue.JobMessage{
		JobID:      jobID,
		UserID:     scanUserID,
		TargetURL:  req.TargetURL,
		ConfigYAML: string(yamlBytes),
		ConfigHash: cfgHash,
	}

	if err := queue.Enqueue(r.Context(), h.rdb, job); err != nil {
		log.Printf("Enqueue error: %v", err)
		db.UpdateScanStatus(r.Context(), h.pool, jobID, "FAILED")
		http.Error(w, "failed to queue scan", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":        jobID,
		"jobId":     jobID,
		"targetUrl": req.TargetURL,
		"status":    "QUEUED",
	})
}

// decodeCreateScanRequest decodes and sanitizes the create-scan body, writing a
// 400 response and returning ok=false when invalid.
func decodeCreateScanRequest(w http.ResponseWriter, r *http.Request) (createScanRequest, bool) {
	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return req, false
	}
	req.TargetURL = sanitizeInput(req.TargetURL)
	req.Login = sanitizeInput(req.Login)
	req.Password = sanitizeInput(req.Password)
	req.AuthURL = sanitizeInput(req.AuthURL)
	req.VerifyURL = sanitizeInput(req.VerifyURL)
	req.StartPoints = sanitizeMultilineInput(req.StartPoints)
	if !isValidURL(req.TargetURL) {
		http.Error(w, "invalid target URL", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// buildCreateScanYAML renders the scan-as-code YAML for a create request.
func buildCreateScanYAML(jobID string, req createScanRequest) ([]byte, error) {
	var startLines []string
	for _, line := range strings.Split(req.StartPoints, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			startLines = append(startLines, line)
		}
	}
	return webscan.BuildScanYAML(webscan.CreateOptions{
		JobID:                 jobID,
		Target:                req.TargetURL,
		Login:                 req.Login,
		Password:              req.Password,
		AuthURL:               req.AuthURL,
		VerifyURL:             req.VerifyURL,
		KatanaDepth:           req.KatanaDepth,
		KatanaMaxURLs:         req.KatanaMaxURLs,
		ZapSpiderMinutes:      req.ZapSpiderMinutes,
		ZapPassiveSecs:        req.ZapPassiveSecs,
		StartPoints:           startLines,
		InsecureSkipTLSVerify: req.InsecureSkipTLSVerify,
	})
}

func (h *Handler) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUser(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}

	findingsCount, _ := db.CountFindingsByScanID(r.Context(), h.pool, scan.ID, db.FindingsQuery{})
	if findingsCount == 0 && (scan.Status == "SUCCEEDED" || scan.Status == "PARTIAL_SUCCESS" || scan.Status == "FAILED") {
		if legacy := loadLegacyFindingsSlice(h.workDir, scan); len(legacy) > 0 {
			findingsCount = len(legacy)
		}
	}

	resp := map[string]interface{}{
		"id":             scan.ID,
		"jobId":          scan.JobID,
		"targetUrl":      scan.TargetURL,
		"status":         scan.Status,
		"createdAt":      scan.CreatedAt,
		"finishedAt":     scan.FinishedAt,
		"findingsCount":  findingsCount,
	}
	if j, err := storage.ReadJob(h.workDir, scan.JobID); err == nil {
		if j.DiscoveryURLsCount > 0 {
			resp["discoveryUrlsCount"] = j.DiscoveryURLsCount
		}
		if len(j.ScannedEndpoints) > 0 {
			resp["endpointCount"] = len(j.ScannedEndpoints)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUserWritable(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}

	if err := db.DeleteScan(r.Context(), h.pool, scan.JobID); err != nil {
		log.Printf("DeleteScan error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUser(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	jobID := scan.JobID

	j, readErr := storage.ReadJob(h.workDir, jobID)
	if readErr != nil {
		log.Printf("ScanStatus: ReadJob failed for %s: %v (workDir=%s)", jobID, readErr, h.workDir)
		j = nil
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
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         scan.Status,
		"elapsedSeconds": elapsedSeconds,
		"progress":       progress,
		"completedSteps": completedSteps,
		"totalSteps":     totalSteps,
		"steps":          steps,
	})
}

func (h *Handler) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUserWritable(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}

	if isTerminalStatus(scan.Status) {
		http.Error(w, "cannot cancel scan with status "+scan.Status, http.StatusBadRequest)
		return
	}

	if err := queue.SetCancelFlag(r.Context(), h.rdb, scan.JobID); err != nil {
		log.Printf("SetCancelFlag error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Reflect cancel request immediately in UI; worker observes flag and stops on the next checkpoint.
	if err := db.UpdateScanStatus(r.Context(), h.pool, scan.JobID, "CANCELLED"); err != nil {
		log.Printf("UpdateScanStatus(cancel) warning for %s: %v", scan.JobID, err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "CANCELLED"})
}

func (h *Handler) handleRestartScan(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUserWritable(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}

	switch scan.Status {
	case "SUCCEEDED", "FAILED", "CANCELED", "CANCELLED":
		// restartable
	default:
		http.Error(w, "can only restart scans with status SUCCEEDED, FAILED, or CANCELLED", http.StatusBadRequest)
		return
	}

	newJobID := uuid.NewString()

	configYAML, err := os.ReadFile(storage.ScanConfigPath(h.workDir, scan.JobID))
	if err != nil {
		log.Printf("RestartScan: config snapshot missing for %s: %v", scan.JobID, err)
		http.Error(w, "scan config not found; cannot restart", http.StatusBadRequest)
		return
	}
	configHash := scan.ConfigHash
	if configHash == "" {
		configHash = storage.ConfigHashSHA256(configYAML)
	}

	if _, err := db.CreateScan(r.Context(), h.pool, scan.UserID, newJobID, scan.TargetURL, configHash); err != nil {
		log.Printf("RestartScan create scan error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	job := queue.JobMessage{
		JobID:      newJobID,
		UserID:     scan.UserID,
		TargetURL:  scan.TargetURL,
		ConfigYAML: string(configYAML),
		ConfigHash: configHash,
	}

	if err := queue.Enqueue(r.Context(), h.rdb, job); err != nil {
		log.Printf("RestartScan enqueue error: %v", err)
		_ = db.UpdateScanStatus(r.Context(), h.pool, newJobID, "FAILED")
		http.Error(w, "failed to queue scan", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":        newJobID,
		"jobId":     newJobID,
		"targetUrl": scan.TargetURL,
		"status":    "QUEUED",
	})
}

func (h *Handler) resolveScanCreateMeta(ctx context.Context, c *auth.Claims) (scanUserID string, ciTokenID *string, source string, err error) {
	scanUserID = c.UserID
	source = "web"
	if authSourceFromContext(ctx) != authSourceCIToken {
		return scanUserID, nil, source, nil
	}
	source = "jenkins"
	id := ciTokenIDFromContext(ctx)
	if id == "" {
		return scanUserID, nil, source, nil
	}
	ciTokenID = &id
	ownerID, err := db.GetCITokenOwnerUserID(ctx, h.pool, id)
	if err != nil {
		return "", nil, "", err
	}
	if ownerID != "" {
		scanUserID = ownerID
	}
	return scanUserID, ciTokenID, source, nil
}
