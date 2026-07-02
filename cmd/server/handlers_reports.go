package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/box-extruder/dast/internal/storage"
)

func (h *Handler) handleReports(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUser(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	jobID := scan.JobID
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))

	reportsDir := filepath.Join(h.workDir, "jobs", jobID, "reports")

	switch format {
	case "html":
		serveReportFile(w, filepath.Join(reportsDir, "report.html"),
			"text/html; charset=utf-8", fmt.Sprintf("report-%s.html", jobID[:8]))
		return
	case "docx", "word":
		serveReportFile(w, filepath.Join(reportsDir, "report.docx"),
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			fmt.Sprintf("report-%s.docx", jobID[:8]))
		return
	case "pdf":
		serveReportFile(w, filepath.Join(reportsDir, "report.pdf"),
			"application/pdf", fmt.Sprintf("report-%s.pdf", jobID[:8]))
		return
	case "endpoints", "discovered-urls":
		data, err := loadScanURLListBytes(h.workDir, jobID)
		if err != nil || len(data) == 0 {
			http.Error(w, "endpoints not found", http.StatusNotFound)
			return
		}
		name := "endpoints"
		if format == "discovered-urls" {
			name = "discovered_urls"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-%s.txt\"", name, jobID[:8]))
		w.Write(data)
		return
	default:
		http.Error(w, "unsupported format; use html, docx or pdf", http.StatusBadRequest)
	}
}

func serveReportFile(w http.ResponseWriter, path, contentType, filename string) {
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "report not found; wait for scan to finish", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Write(data)
}

func (h *Handler) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUser(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	jobID := scan.JobID
	urls := loadScanURLList(h.workDir, jobID)
	if len(urls) == 0 {
		http.Error(w, "endpoints not found", http.StatusNotFound)
		return
	}
	limit, offset := parsePagination(r)
	if limit <= 0 {
		limit = 100
	}
	items, total := paginateStringList(urls, limit, offset, r.URL.Query().Get("q"))
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// loadScanURLList prefers full discovery feed, then endpoints.txt, then job.json.
func loadScanURLList(workDir, jobID string) []string {
	if urls, err := storage.LoadDiscoveredURLsTxt(workDir, jobID); err == nil && len(urls) > 0 {
		return urls
	}
	if urls, err := storage.LoadEndpointsTxt(workDir, jobID); err == nil && len(urls) > 0 {
		return urls
	}
	if j, err := storage.ReadJob(workDir, jobID); err == nil && len(j.ScannedEndpoints) > 0 {
		return j.ScannedEndpoints
	}
	return nil
}

func loadScanURLListBytes(workDir, jobID string) ([]byte, error) {
	urls := loadScanURLList(workDir, jobID)
	if len(urls) == 0 {
		return nil, fmt.Errorf("no urls")
	}
	return []byte(strings.Join(urls, "\n") + "\n"), nil
}

func (h *Handler) handleDiscoveredURLs(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUser(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	urls, err := storage.LoadDiscoveredURLsTxt(h.workDir, scan.JobID)
	if err != nil || len(urls) == 0 {
		urls = loadScanURLList(h.workDir, scan.JobID)
	}
	if len(urls) == 0 {
		http.Error(w, "discovered urls not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, urls)
}
