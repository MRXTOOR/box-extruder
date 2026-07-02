package main

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/google/uuid"
)

func parsePagination(r *http.Request) (limit, offset int) {
	limit = 50
	offset = 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 200 {
		limit = 200
	}
	if v := strings.TrimSpace(r.URL.Query().Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func (h *Handler) handleGetScanFindings(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUser(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	limit, offset := parsePagination(r)
	q := db.FindingsQuery{
		Limit:    limit,
		Offset:   offset,
		Severity: r.URL.Query().Get("severity"),
		Q:        r.URL.Query().Get("q"),
	}
	items, total, err := db.GetFindingsByScanIDPaginated(r.Context(), h.pool, scan.ID, q)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if len(items) == 0 && total == 0 {
		if legacy := loadLegacyFindingsSlice(h.workDir, scan); len(legacy) > 0 {
			filtered := filterLegacyFindings(legacy, q)
			total = len(filtered)
			if offset < total {
				end := offset + limit
				if end > total {
					end = total
				}
				items = filtered[offset:end]
			}
		}
	}
	for i := range items {
		items[i] = enrichFindingEndpoint(items[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *Handler) handleGetScanFindingsCounts(w http.ResponseWriter, r *http.Request) {
	scan, _, err := h.getScanForUser(r)
	if err != nil {
		writeScanAccessError(w, err)
		return
	}
	counts, err := db.GetFindingSeverityCounts(r.Context(), h.pool, scan.ID)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if len(counts) == 0 {
		if legacy := loadLegacyFindingsSlice(h.workDir, scan); len(legacy) > 0 {
			counts = map[string]int{}
			for _, f := range legacy {
				sev := strings.ToUpper(strings.TrimSpace(f.Severity))
				if sev == "" {
					sev = "INFO"
				}
				counts[sev]++
			}
		}
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	counts["ALL"] = total
	writeJSON(w, http.StatusOK, counts)
}

func loadLegacyFindingsSlice(workDir string, scan *db.Scan) []db.Finding {
	if scan.Status != "SUCCEEDED" && scan.Status != "PARTIAL_SUCCESS" && scan.Status != "FAILED" {
		return nil
	}
	fileFindings, err := storage.LoadFindingsJSON(workDir, scan.JobID, "findings-final.json")
	if err != nil {
		return nil
	}
	out := make([]db.Finding, 0, len(fileFindings))
	for _, f := range fileFindings {
		out = append(out, db.Finding{
			ID:           uuid.NewString(),
			ScanID:       scan.ID,
			Name:         f.Title,
			Severity:     string(f.Severity),
			Description:  f.Description,
			EndpointPath: noise.EndpointURLFromLocationKey(f.LocationKey),
		})
	}
	return out
}

func filterLegacyFindings(items []db.Finding, q db.FindingsQuery) []db.Finding {
	sev := strings.ToUpper(strings.TrimSpace(q.Severity))
	text := strings.ToLower(strings.TrimSpace(q.Q))
	var out []db.Finding
	for _, f := range items {
		if sev != "" && sev != "ALL" && strings.ToUpper(f.Severity) != sev {
			continue
		}
		if text != "" {
			blob := strings.ToLower(f.Name + " " + f.Description + " " + f.EndpointPath)
			if !strings.Contains(blob, text) {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

func paginateStringList(all []string, limit, offset int, q string) ([]string, int) {
	if text := strings.ToLower(strings.TrimSpace(q)); text != "" {
		filtered := make([]string, 0, len(all))
		for _, u := range all {
			if strings.Contains(strings.ToLower(u), text) {
				filtered = append(filtered, u)
			}
		}
		all = filtered
	}
	total := len(all)
	if offset >= total {
		return []string{}, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}
