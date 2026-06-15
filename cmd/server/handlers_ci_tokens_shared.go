package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/enterprise/db"
)

type createCiTokenInput struct {
	Name        string
	OwnerUserID string
	CreatedBy   string
	ExpiresDays *int
	ExpiresAt   *string
}

func ensureCiTokenName(name string) (string, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		id := strings.ReplaceAll(strings.ToLower(fmt.Sprintf("%x", time.Now().UnixNano())), "-", "")
		if len(id) > 8 {
			id = id[len(id)-8:]
		}
		name = "key-" + id
	}
	return parseCiTokenName(name)
}

func parseExpiresAt(expiresAt *string, expiresDays *int) (*time.Time, error) {
	if expiresAt != nil {
		raw := strings.TrimSpace(*expiresAt)
		if raw != "" {
			t, err := time.Parse("2006-01-02", raw)
			if err != nil {
				return nil, fmt.Errorf("invalid expiresAt: use YYYY-MM-DD")
			}
			end := time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
			if !end.After(time.Now().UTC()) {
				return nil, fmt.Errorf("expiresAt must be in the future")
			}
			return &end, nil
		}
	}
	return expiresAtFromDays(expiresDays), nil
}

func parseCiTokenName(name string) (string, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if !ciTokenNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid name: use lowercase letters, digits, hyphens")
	}
	return name, nil
}

func expiresAtFromDays(expiresDays *int) *time.Time {
	if expiresDays == nil || *expiresDays <= 0 {
		return nil
	}
	t := time.Now().UTC().Add(time.Duration(*expiresDays) * 24 * time.Hour)
	return &t
}

func (h *Handler) issueCIToken(ctx context.Context, in createCiTokenInput) (map[string]any, error) {
	name, err := ensureCiTokenName(in.Name)
	if err != nil {
		return nil, err
	}
	if in.OwnerUserID == "" {
		return nil, fmt.Errorf("owner required")
	}
	owner, err := db.GetUserByID(ctx, h.pool, in.OwnerUserID)
	if err != nil {
		return nil, fmt.Errorf("owner user not found")
	}
	if owner.Role != "admin" && owner.Role != "specialist" {
		return nil, fmt.Errorf("owner must be specialist or admin")
	}

	expiresAt, err := parseExpiresAt(in.ExpiresAt, in.ExpiresDays)
	if err != nil {
		return nil, err
	}

	serviceUser, err := db.EnsureServiceUser(ctx, h.pool, name)
	if err != nil {
		return nil, fmt.Errorf("ensure service user: %w", err)
	}

	ownerID := in.OwnerUserID
	createdBy := in.CreatedBy
	secret, token, err := db.CreateCITokenWithOwner(ctx, h.pool, db.CreateCITokenParams{
		ServiceUserID: serviceUser.ID,
		Name:          name,
		OwnerUserID:   &ownerID,
		CreatedBy:     &createdBy,
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	return map[string]any{
		"secret":              secret,
		"token":                 token,
		"ownerLogin":            owner.Login,
		"serviceUserLogin":      serviceUser.Login,
		"jenkinsCredentialId":   "dast-ci-" + name,
	}, nil
}

func writeCiTokenCreateError(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "invalid name"):
		http.Error(w, msg, http.StatusBadRequest)
	case strings.Contains(msg, "invalid expiresAt"), strings.Contains(msg, "expiresAt must"):
		http.Error(w, msg, http.StatusBadRequest)
	case strings.Contains(msg, "owner user not found"), strings.Contains(msg, "owner must"):
		http.Error(w, msg, http.StatusBadRequest)
	case strings.Contains(msg, "owner required"):
		http.Error(w, msg, http.StatusBadRequest)
	default:
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
