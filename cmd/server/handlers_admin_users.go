package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/box-extruder/dast/internal/enterprise/db"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := db.GetUsers(r.Context(), h.pool)
	if err != nil {
		log.Printf("GetUsers: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	type userRow struct {
		db.User
		CITokenCount int `json:"ciTokenCount"`
	}
	out := make([]userRow, 0, len(users))
	for _, u := range users {
		tokens, _ := db.ListCITokensByOwner(r.Context(), h.pool, u.ID)
		out = append(out, userRow{User: u, CITokenCount: len(tokens)})
	}
	writeJSON(w, http.StatusOK, out)
}

type createUserRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (h *Handler) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Login = sanitizeInput(strings.TrimSpace(req.Login))
	if req.Login == "" || req.Password == "" {
		http.Error(w, "login and password required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "specialist"
	}
	if req.Role != "admin" && req.Role != "specialist" {
		http.Error(w, "role must be admin or specialist", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	user, err := db.CreateUser(r.Context(), h.pool, req.Login, string(hash), req.Role)
	if err != nil {
		log.Printf("CreateUser: %v", err)
		http.Error(w, "could not create user", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (h *Handler) handleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	id := extractPathParam(r.URL.Path, "/api/v1/admin/users/")
	if id == "" {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	user, err := db.GetUserByID(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	tokens, _ := db.ListCITokensByOwner(r.Context(), h.pool, id)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"ciTokens": tokens,
	})
}

type patchUserRequest struct {
	Role string `json:"role"`
}

func (h *Handler) handleAdminPatchUser(w http.ResponseWriter, r *http.Request) {
	id := extractPathParam(r.URL.Path, "/api/v1/admin/users/")
	if id == "" {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	var req patchUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Role != "admin" && req.Role != "specialist" {
		http.Error(w, "role must be admin or specialist", http.StatusBadRequest)
		return
	}
	user, err := db.GetUserByID(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if user.Role == "admin" && req.Role != "admin" {
		n, _ := db.CountAdmins(r.Context(), h.pool)
		if n <= 1 {
			http.Error(w, "cannot demote the only admin", http.StatusBadRequest)
			return
		}
	}
	updated, err := db.UpdateUserRole(r.Context(), h.pool, id, req.Role)
	if err != nil {
		log.Printf("UpdateUserRole: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := extractPathParam(r.URL.Path, "/api/v1/admin/users/")
	if id == "" {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if claims.UserID == id {
		http.Error(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}
	user, err := db.GetUserByID(r.Context(), h.pool, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if user.Role == "admin" {
		n, _ := db.CountAdmins(r.Context(), h.pool)
		if n <= 1 {
			http.Error(w, "cannot delete the only admin", http.StatusBadRequest)
			return
		}
	}
	if err := db.DeleteUserByID(r.Context(), h.pool, id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("DeleteUserByID: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	log.Printf("User deleted id=%s login=%s by admin=%s", id, user.Login, claims.Login)
	w.WriteHeader(http.StatusNoContent)
}
