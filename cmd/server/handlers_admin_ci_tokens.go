package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/box-extruder/dast/internal/enterprise/db"
)

var ciTokenNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

type verifyCITokenRequest struct {
	Token string `json:"token"`
}

func (h *Handler) handleAdminVerifyCIToken(w http.ResponseWriter, r *http.Request) {
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
	user, err := db.AuthenticateCIToken(r.Context(), h.pool, req.Token)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}
	item, _ := db.GetCITokenListItem(r.Context(), h.pool, ciID)
	out := map[string]any{
		"valid":  true,
		"login":  user.Login,
		"role":   user.Role,
		"userId": user.ID,
	}
	if item != nil {
		out["tokenId"] = item.ID
		out["name"] = item.Name
		out["status"] = item.Status
		out["ownerLogin"] = item.OwnerLogin
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleAdminListCITokens(w http.ResponseWriter, r *http.Request) {
	items, err := db.ListCITokensAdmin(r.Context(), h.pool)
	if err != nil {
		log.Printf("ListCITokensAdmin: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if items == nil {
		items = []db.CITokenListItem{}
	}
	writeJSON(w, http.StatusOK, items)
}

type createCITokenRequest struct {
	Name        string  `json:"name"`
	OwnerUserID string  `json:"ownerUserId"`
	ExpiresDays *int    `json:"expiresDays"`
	ExpiresAt   *string `json:"expiresAt"`
}

func (h *Handler) handleAdminCreateCIToken(w http.ResponseWriter, r *http.Request) {
	if h.loginLimiter != nil && !h.loginLimiter.allow("ci-token-create:"+clientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createCITokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.OwnerUserID == "" {
		http.Error(w, "ownerUserId required", http.StatusBadRequest)
		return
	}

	out, err := h.issueCIToken(r.Context(), createCiTokenInput{
		Name:        req.Name,
		OwnerUserID: req.OwnerUserID,
		CreatedBy:   claims.UserID,
		ExpiresDays: req.ExpiresDays,
		ExpiresAt:   req.ExpiresAt,
	})
	if err != nil {
		log.Printf("issueCIToken (admin): %v", err)
		writeCiTokenCreateError(w, err)
		return
	}

	log.Printf("CI token created name=%s owner=%s by admin=%s", req.Name, out["ownerLogin"], claims.Login)
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) handleAdminGetCIToken(w http.ResponseWriter, r *http.Request) {
	id := extractPathParam(r.URL.Path, "/api/v1/admin/ci-tokens/")
	if id == "" {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	item, err := db.GetCITokenListItem(r.Context(), h.pool, id)
	if err != nil {
		if err == db.ErrCITokenNotFound {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("GetCITokenListItem: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type patchCITokenRequest struct {
	OwnerUserID string `json:"ownerUserId"`
}

func (h *Handler) handleAdminPatchCIToken(w http.ResponseWriter, r *http.Request) {
	id := extractPathParam(r.URL.Path, "/api/v1/admin/ci-tokens/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	var req patchCITokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.OwnerUserID == "" {
		http.Error(w, "ownerUserId required", http.StatusBadRequest)
		return
	}
	old, _ := db.GetCITokenListItem(r.Context(), h.pool, id)
	if _, err := db.GetUserByID(r.Context(), h.pool, req.OwnerUserID); err != nil {
		http.Error(w, "owner user not found", http.StatusBadRequest)
		return
	}
	if err := db.UpdateCITokenOwner(r.Context(), h.pool, id, req.OwnerUserID); err != nil {
		if err == db.ErrCITokenNotFound {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("UpdateCITokenOwner: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if old != nil {
		log.Printf("CI token %s owner changed from %s to %s by %s", id, old.OwnerUserID, req.OwnerUserID, claims.Login)
	}
	item, _ := db.GetCITokenListItem(r.Context(), h.pool, id)
	writeJSON(w, http.StatusOK, item)
}

func (h *Handler) handleAdminRevokeCIToken(w http.ResponseWriter, r *http.Request) {
	id := extractPathParam(r.URL.Path, "/api/v1/admin/ci-tokens/")
	if id == "" {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := db.RevokeCITokenIdempotent(r.Context(), h.pool, id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("RevokeCIToken: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	log.Printf("CI token revoked id=%s by admin=%s", id, claims.Login)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleAdminCITokenScans(w http.ResponseWriter, r *http.Request) {
	prefix := "/api/v1/admin/ci-tokens/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[1] != "scans" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	tokenID := parts[0]
	if _, err := db.GetCITokenListItem(r.Context(), h.pool, tokenID); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
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

func extractPathParam(path, prefix string) string {
	s := strings.TrimPrefix(path, prefix)
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
