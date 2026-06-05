package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/box-extruder/dast/internal/auth/discovery"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	remoteKey := remoteAddrKey(r.RemoteAddr)
	if h.loginLimiter != nil && !h.loginLimiter.allow(remoteKey) {
		http.Error(w, "too many login attempts, try later", http.StatusTooManyRequests)
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
		if h.loginLimiter != nil {
			h.loginLimiter.fail(remoteKey)
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		if h.loginLimiter != nil {
			h.loginLimiter.fail(remoteKey)
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if h.loginLimiter != nil {
		h.loginLimiter.reset(remoteKey)
	}

	token, err := h.auth.GenerateToken(user.ID, user.Login, user.Role)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token": token,
		"user":  user.Login,
		"role":  user.Role,
	})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":    c.UserID,
		"login": c.Login,
		"role":  c.Role,
	})
}

func (h *Handler) handleAuthDiscover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetURL             string `json:"targetUrl"`
		InsecureSkipTLSVerify bool   `json:"insecureSkipTlsVerify"`
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
	if err := validateDiscoverTargetURL(req.TargetURL); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := discovery.DiscoverSurface(req.TargetURL, req.InsecureSkipTLSVerify)
	writeJSON(w, http.StatusOK, res)
}
