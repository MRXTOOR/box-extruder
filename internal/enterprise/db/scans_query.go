package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const scanSelectCols = `id, user_id, job_id, target_url, status, config_hash, ci_token_id, source, metadata, created_at, updated_at, finished_at`

func scanRow(row pgx.Row) (*Scan, error) {
	var s Scan
	var ciTokenID *string
	var meta []byte
	err := row.Scan(
		&s.ID, &s.UserID, &s.JobID, &s.TargetURL, &s.Status, &s.ConfigHash,
		&ciTokenID, &s.Source, &meta, &s.CreatedAt, &s.UpdatedAt, &s.FinishedAt,
	)
	if err != nil {
		return nil, err
	}
	s.CITokenID = ciTokenID
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &s.Metadata)
	}
	if s.Source == "" {
		s.Source = "web"
	}
	return &s, nil
}

func scanRows(rows pgx.Rows) ([]Scan, error) {
	var scans []Scan
	for rows.Next() {
		var s Scan
		var ciTokenID *string
		var meta []byte
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.JobID, &s.TargetURL, &s.Status, &s.ConfigHash,
			&ciTokenID, &s.Source, &meta, &s.CreatedAt, &s.UpdatedAt, &s.FinishedAt,
		); err != nil {
			return nil, err
		}
		s.CITokenID = ciTokenID
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &s.Metadata)
		}
		if s.Source == "" {
			s.Source = "web"
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// ScanWithFindingsCount extends Scan with findings count for list views.
type ScanWithFindingsCount struct {
	Scan
	FindingsCount int `json:"findingsCount"`
}

// CreateScanParams holds fields for CreateScanWithMeta.
type CreateScanParams struct {
	UserID     string
	JobID      string
	TargetURL  string
	ConfigHash string
	CITokenID  *string
	Source     string
}

// CreateScanWithMeta inserts a scan with optional CI token linkage.
func CreateScanWithMeta(ctx context.Context, pool *pgxpool.Pool, p CreateScanParams) (*Scan, error) {
	if p.Source == "" {
		p.Source = "web"
	}
	row := pool.QueryRow(ctx,
		`INSERT INTO scans (user_id, job_id, target_url, config_hash, ci_token_id, source)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+scanSelectCols,
		p.UserID, p.JobID, p.TargetURL, p.ConfigHash, p.CITokenID, p.Source,
	)
	return scanRow(row)
}

func GetScansByCITokenID(ctx context.Context, pool *pgxpool.Pool, ciTokenID string, limit, offset int) ([]ScanWithFindingsCount, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := pool.Query(ctx,
		`SELECT s.id, s.user_id, s.job_id, s.target_url, s.status, s.config_hash, s.ci_token_id, s.source, s.metadata,
		        s.created_at, s.updated_at, s.finished_at,
		        COALESCE((SELECT COUNT(*)::int FROM findings f WHERE f.scan_id = s.id), 0) AS findings_count
		 FROM scans s
		 WHERE s.ci_token_id = $1
		 ORDER BY s.created_at DESC
		 LIMIT $2 OFFSET $3`,
		ciTokenID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanWithFindingsCount
	for rows.Next() {
		var item ScanWithFindingsCount
		var ciID *string
		var meta []byte
		if err := rows.Scan(
			&item.ID, &item.UserID, &item.JobID, &item.TargetURL, &item.Status, &item.ConfigHash,
			&ciID, &item.Source, &meta, &item.CreatedAt, &item.UpdatedAt, &item.FinishedAt,
			&item.FindingsCount,
		); err != nil {
			return nil, err
		}
		item.CITokenID = ciID
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &item.Metadata)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func CountScansByCITokenID(ctx context.Context, pool *pgxpool.Pool, ciTokenID string) (int, error) {
	var n int
	err := pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM scans WHERE ci_token_id = $1`, ciTokenID).Scan(&n)
	return n, err
}

// GetCITokenOwnerUserID returns owner_user_id for a CI token, or empty if unset.
func GetCITokenOwnerUserID(ctx context.Context, pool *pgxpool.Pool, ciTokenID string) (string, error) {
	var ownerID *string
	err := pool.QueryRow(ctx,
		`SELECT owner_user_id FROM ci_tokens WHERE id = $1`,
		ciTokenID,
	).Scan(&ownerID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", ErrCITokenNotFound
		}
		return "", err
	}
	if ownerID == nil {
		return "", nil
	}
	return *ownerID, nil
}

// IsCITokenOwner returns true if userID owns the CI token (owner_user_id).
func IsCITokenOwner(ctx context.Context, pool *pgxpool.Pool, ciTokenID, userID string) (bool, error) {
	var ownerID *string
	err := pool.QueryRow(ctx,
		`SELECT owner_user_id FROM ci_tokens WHERE id = $1`,
		ciTokenID,
	).Scan(&ownerID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if ownerID == nil {
		return false, nil
	}
	return *ownerID == userID, nil
}

// UpdateScanMetadata merges JSON metadata into scans.metadata.
func UpdateScanMetadata(ctx context.Context, pool *pgxpool.Pool, jobID string, patch map[string]any) error {
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	tag, err := pool.Exec(ctx,
		`UPDATE scans SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE job_id = $2`,
		data, jobID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("scan not found")
	}
	return nil
}

func UpdateUserRole(ctx context.Context, pool *pgxpool.Pool, userID, role string) (*User, error) {
	var u User
	err := pool.QueryRow(ctx,
		`UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1
		 RETURNING id, login, role, created_at`,
		userID, role,
	).Scan(&u.ID, &u.Login, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func CountAdmins(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}
