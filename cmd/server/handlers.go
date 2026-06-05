package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/box-extruder/dast/internal/enterprise/auth"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/noise"
)

// Sentinel errors for scan access resolution; mapped to HTTP status by writeScanAccessError.
var (
	errUnauthorized  = errors.New("unauthorized")
	errInvalidToken  = errors.New("invalid token")
	errForbidden     = errors.New("forbidden")
	errInvalidScanID = errors.New("invalid scan id")
	errScanNotFound  = errors.New("scan not found")
)

// writeJSON serializes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// resolveScan looks up a scan by its UUID first, then falls back to job id.
func (h *Handler) resolveScan(ctx context.Context, id string) (*db.Scan, error) {
	if scan, err := db.GetScanByID(ctx, h.pool, id); err == nil {
		return scan, nil
	}
	return db.GetScanByJobID(ctx, h.pool, id)
}

// getScanForUser resolves scan by path id (scan UUID or jobId) and enforces owner/admin access.
func (h *Handler) getScanForUser(r *http.Request) (*db.Scan, *auth.Claims, error) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		return nil, nil, errUnauthorized
	}
	jobID := extractJobID(r.URL.Path)
	if jobID == "" {
		return nil, nil, errInvalidScanID
	}
	scan, err := h.resolveScan(r.Context(), jobID)
	if err != nil {
		return nil, nil, errScanNotFound
	}
	if scan.UserID != c.UserID && c.Role != "admin" {
		return nil, nil, errForbidden
	}
	return scan, c, nil
}

func writeScanAccessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, errInvalidToken):
		http.Error(w, "invalid token", http.StatusUnauthorized)
	case errors.Is(err, errForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, errInvalidScanID):
		http.Error(w, "invalid scan id", http.StatusBadRequest)
	case errors.Is(err, errScanNotFound):
		http.Error(w, "scan not found", http.StatusNotFound)
	default:
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// isTerminalStatus reports whether a scan has reached a final state.
func isTerminalStatus(status string) bool {
	switch status {
	case "SUCCEEDED", "FAILED", "PARTIAL_SUCCESS", "CANCELED", "CANCELLED":
		return true
	default:
		return false
	}
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

func sanitizeMultilineInput(input string) string {
	// Keep line breaks for textarea fields such as startPoints.
	// Drop control characters except LF/CR/TAB.
	input = regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`).ReplaceAllString(input, "")
	// Normalize Windows line endings to '\n' so server splitting is stable.
	input = strings.ReplaceAll(input, "\r\n", "\n")
	return input
}

func enrichFindingEndpoint(f db.Finding) db.Finding {
	if strings.HasPrefix(f.EndpointPath, "http://") || strings.HasPrefix(f.EndpointPath, "https://") {
		return f
	}
	if f.Evidence != nil {
		if lk, ok := f.Evidence["locationKey"].(string); ok {
			if full := noise.EndpointURLFromLocationKey(lk); full != "" {
				f.EndpointPath = full
			}
		}
	}
	return f
}
