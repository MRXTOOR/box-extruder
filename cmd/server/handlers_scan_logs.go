package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/storage"
)

func (h *Handler) handleScanDump(w http.ResponseWriter, r *http.Request) {
	acc, err := h.resolveScanAccess(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	jobID := acc.scan.JobID
	if st, err := os.Stat(storage.JobRoot(h.workDir, jobID)); err != nil || !st.IsDir() {
		http.Error(w, "dump not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dast-dump-%s.zip"`, jobID))
	if err := storage.BuildScanDump(h.workDir, jobID, w, storage.DefaultDumpMaxBytes); err != nil {
		log.Printf("BuildScanDump %s: %v", jobID, err)
	}
}

func (h *Handler) handleScanLogs(w http.ResponseWriter, r *http.Request) {
	acc, err := h.resolveScanAccess(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	findings, _ := db.GetFindingsByScanID(r.Context(), h.pool, acc.scan.ID)
	resp, err := storage.LoadScanLogs(storage.ScanLogsParams{
		WorkDir:       h.workDir,
		JobID:         acc.scan.JobID,
		Status:        acc.scan.Status,
		TargetURL:     acc.scan.TargetURL,
		FindingsCount: len(findings),
		LevelParam:    r.URL.Query().Get("level"),
		Tail:          tail,
	})
	if err != nil {
		log.Printf("LoadScanLogs: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type ciMetadataRequest struct {
	JobName   string `json:"jobName"`
	BuildNum  string `json:"buildNumber"`
	BuildURL  string `json:"buildUrl"`
	Console   string `json:"consoleSnippet,omitempty"`
}

func (h *Handler) handleScanCIMetadata(w http.ResponseWriter, r *http.Request) {
	if authSourceFromContext(r.Context()) != authSourceCIToken {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	acc, err := h.resolveScanAccess(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	var req ciMetadataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	meta := map[string]any{
		"jenkinsJob":   req.JobName,
		"jenkinsBuild": req.BuildNum,
		"jenkinsUrl":   req.BuildURL,
	}
	if req.Console != "" {
		meta["consoleSnippet"] = req.Console
	}
	if err := db.UpdateScanMetadata(r.Context(), h.pool, acc.scan.JobID, meta); err != nil {
		log.Printf("UpdateScanMetadata: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// also write to disk
	_ = storage.WriteJSONFile(storage.JobRoot(h.workDir, acc.scan.JobID)+"/ci/jenkins.json", meta)
	writeJSON(w, http.StatusOK, meta)
}
