package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/box-extruder/dast/internal/enterprise/db"
)

type meCreateCITokenRequest struct {
	Name        string  `json:"name"`
	ExpiresDays *int    `json:"expiresDays"`
	ExpiresAt   *string `json:"expiresAt"`
}

func (h *Handler) handleMeCreateCIToken(w http.ResponseWriter, r *http.Request) {
	if h.loginLimiter != nil && !h.loginLimiter.allow("ci-token-create:"+clientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req meCreateCITokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	out, err := h.issueCIToken(r.Context(), createCiTokenInput{
		Name:        req.Name,
		OwnerUserID: claims.UserID,
		CreatedBy:   claims.UserID,
		ExpiresDays: req.ExpiresDays,
		ExpiresAt:   req.ExpiresAt,
	})
	if err != nil {
		log.Printf("issueCIToken (me): %v", err)
		writeCiTokenCreateError(w, err)
		return
	}

	log.Printf("CI token created name=%s owner=%s (self-service)", req.Name, claims.Login)
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) handleMeVerifyCIToken(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req verifyCITokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}

	ciID, err := db.ParseCITokenIDFromSecret(req.Token)
	if err != nil {
		http.Error(w, "invalid token format", http.StatusBadRequest)
		return
	}
	if _, err := db.AuthenticateCIToken(r.Context(), h.pool, req.Token); err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}
	item, err := db.GetCITokenListItem(r.Context(), h.pool, ciID)
	if err != nil || item.OwnerUserID != claims.UserID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":              true,
		"name":               item.Name,
		"status":             item.Status,
		"jenkinsCredentialId": item.JenkinsCredID,
	})
}

func (h *Handler) handleMeRevokeCIToken(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := extractPathParam(r.URL.Path, "/api/v1/me/ci-tokens/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	item, err := db.GetCITokenListItem(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if item.OwnerUserID != claims.UserID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := db.RevokeCITokenIdempotent(r.Context(), h.pool, id); err != nil {
		log.Printf("RevokeCIToken (me): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	log.Printf("CI token revoked id=%s by owner=%s", id, claims.Login)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMeListCITokens(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	items, err := db.ListCITokensByOwner(r.Context(), h.pool, claims.UserID)
	if err != nil {
		log.Printf("ListCITokensByOwner: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if items == nil {
		items = []db.CITokenListItem{}
	}
	writeJSON(w, http.StatusOK, items)
}

func (h *Handler) handleMeCITokenScans(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	prefix := "/api/v1/me/ci-tokens/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[1] != "scans" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	tokenID := parts[0]
	item, err := db.GetCITokenListItem(r.Context(), h.pool, tokenID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if item.OwnerUserID != claims.UserID && claims.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if offset > 0 {
		offset = (offset - 1) * limit
	}
	scans, err := db.GetScansByCITokenID(r.Context(), h.pool, tokenID, limit, offset)
	if err != nil {
		log.Printf("GetScansByCITokenID: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if scans == nil {
		scans = []db.ScanWithFindingsCount{}
	}
	writeJSON(w, http.StatusOK, scans)
}

func (h *Handler) handleMeGetCIToken(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := extractPathParam(r.URL.Path, "/api/v1/me/ci-tokens/")
	if id == "" {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	item, err := db.GetCITokenListItem(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if item.OwnerUserID != claims.UserID && claims.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
