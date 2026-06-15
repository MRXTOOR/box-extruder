package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// CITokenStatus derives active/revoked/expired from token fields.
func CITokenStatus(t *CIToken) string {
	if t.RevokedAt != nil {
		return "revoked"
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return "expired"
	}
	return "active"
}

// CITokenListItem is a token row for admin/owner list APIs (no secret).
type CITokenListItem struct {
	CIToken
	Status          string `json:"status"`
	ServiceUserLogin string `json:"serviceUserLogin"`
	OwnerUserID     string `json:"ownerUserId,omitempty"`
	OwnerLogin      string `json:"ownerLogin,omitempty"`
	CreatedByLogin  string `json:"createdByLogin,omitempty"`
	ScanCount       int    `json:"scanCount"`
	JenkinsCredID   string `json:"jenkinsCredentialId"`
}

// ParseCITokenIDFromSecret extracts UUID from dast_<uuid> secret.
func ParseCITokenIDFromSecret(secret string) (string, error) {
	if !strings.HasPrefix(secret, ciTokenPrefix) {
		return "", ErrCITokenNotFound
	}
	id := strings.TrimSpace(secret[len(ciTokenPrefix):])
	if _, err := uuid.Parse(id); err != nil {
		return "", ErrCITokenNotFound
	}
	return id, nil
}

// CreateCITokenParams holds fields for CreateCITokenWithOwner.
type CreateCITokenParams struct {
	ServiceUserID string
	Name          string
	OwnerUserID   *string
	CreatedBy     *string
	ExpiresAt     *time.Time
}

// CreateCITokenWithOwner creates a token linked to service user, owner, and admin creator.
func CreateCITokenWithOwner(ctx context.Context, pool *pgxpool.Pool, p CreateCITokenParams) (secret string, token *CIToken, err error) {
	id := uuid.New().String()
	secret = FormatCITokenSecret(id)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	var t CIToken
	err = pool.QueryRow(ctx,
		`INSERT INTO ci_tokens (id, user_id, name, token_hash, created_by, owner_user_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, user_id, name, created_at, last_used_at, revoked_at, expires_at`,
		id, p.ServiceUserID, p.Name, string(hash), p.CreatedBy, p.OwnerUserID, p.ExpiresAt,
	).Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.ExpiresAt)
	if err != nil {
		return "", nil, err
	}
	if p.OwnerUserID != nil {
		t.OwnerUserID = *p.OwnerUserID
	}
	if p.CreatedBy != nil {
		t.CreatedBy = *p.CreatedBy
	}
	return secret, &t, nil
}

func listCITokensQuery(where string, args ...any) string {
	q := `SELECT t.id, t.user_id, t.name, t.created_at, t.last_used_at, t.revoked_at, t.expires_at,
	               t.created_by, t.owner_user_id,
	               su.login AS service_login,
	               ou.login AS owner_login,
	               cb.login AS created_by_login,
	               COALESCE((SELECT COUNT(*)::int FROM scans s WHERE s.ci_token_id = t.id), 0) AS scan_count
	        FROM ci_tokens t
	        JOIN users su ON su.id = t.user_id
	        LEFT JOIN users ou ON ou.id = t.owner_user_id
	        LEFT JOIN users cb ON cb.id = t.created_by`
	if where != "" {
		q += " WHERE " + where
	}
	q += " ORDER BY t.created_at DESC"
	return q
}

func scanCITokenListItem(rows pgx.Rows) ([]CITokenListItem, error) {
	var out []CITokenListItem
	for rows.Next() {
		var item CITokenListItem
		var createdBy, ownerUserID *string
		var ownerLogin, createdByLogin *string
		if err := rows.Scan(
			&item.ID, &item.UserID, &item.Name, &item.CreatedAt, &item.LastUsedAt, &item.RevokedAt, &item.ExpiresAt,
			&createdBy, &ownerUserID,
			&item.ServiceUserLogin, &ownerLogin, &createdByLogin,
			&item.ScanCount,
		); err != nil {
			return nil, err
		}
		if ownerUserID != nil {
			item.OwnerUserID = *ownerUserID
		}
		if ownerLogin != nil {
			item.OwnerLogin = *ownerLogin
		}
		if createdByLogin != nil {
			item.CreatedByLogin = *createdByLogin
		}
		if createdBy != nil {
			item.CreatedBy = *createdBy
		}
		item.Status = CITokenStatus(&item.CIToken)
		item.JenkinsCredID = "dast-ci-" + item.Name
		out = append(out, item)
	}
	return out, rows.Err()
}

func ListCITokensAdmin(ctx context.Context, pool *pgxpool.Pool) ([]CITokenListItem, error) {
	rows, err := pool.Query(ctx, listCITokensQuery(""))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCITokenListItem(rows)
}

func ListCITokensByOwner(ctx context.Context, pool *pgxpool.Pool, ownerUserID string) ([]CITokenListItem, error) {
	rows, err := pool.Query(ctx, listCITokensQuery("t.owner_user_id = $1"), ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCITokenListItem(rows)
}

func GetCITokenListItem(ctx context.Context, pool *pgxpool.Pool, id string) (*CITokenListItem, error) {
	rows, err := pool.Query(ctx, listCITokensQuery("t.id = $1"), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items, err := scanCITokenListItem(rows)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrCITokenNotFound
	}
	return &items[0], nil
}

func UpdateCITokenOwner(ctx context.Context, pool *pgxpool.Pool, tokenID, ownerUserID string) error {
	tag, err := pool.Exec(ctx,
		`UPDATE ci_tokens SET owner_user_id = $2 WHERE id = $1 AND revoked_at IS NULL`,
		tokenID, ownerUserID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCITokenNotFound
	}
	return nil
}

// RevokeCITokenIdempotent revokes token or succeeds if already revoked.
func RevokeCITokenIdempotent(ctx context.Context, pool *pgxpool.Pool, id string) error {
	tag, err := pool.Exec(ctx,
		`UPDATE ci_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var revokedAt *time.Time
		err := pool.QueryRow(ctx, `SELECT revoked_at FROM ci_tokens WHERE id = $1`, id).Scan(&revokedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: %s", ErrCITokenNotFound, id)
			}
			return err
		}
		if revokedAt == nil {
			return fmt.Errorf("%w: %s", ErrCITokenNotFound, id)
		}
	}
	return nil
}

// EnsureServiceUser returns ci-{name} user, creating if missing.
func EnsureServiceUser(ctx context.Context, pool *pgxpool.Pool, name string) (*User, error) {
	login := "ci-" + name
	u, err := GetUserByLogin(ctx, pool, login)
	if err == nil {
		return u, nil
	}
	// random unusable password for service account
	hash, err := bcrypt.GenerateFromPassword([]byte(uuid.New().String()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return CreateUser(ctx, pool, login, string(hash), "specialist")
}
