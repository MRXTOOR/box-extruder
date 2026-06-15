package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Pool = pgxpool.Pool

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
}

func Connect(cfg Config) (*pgxpool.Pool, error) {
	// Build the connection config from struct fields rather than an inline
	// URL-style DSN: this keeps credentials out of a formatted string and avoids
	// URL-encoding pitfalls for passwords with special characters.
	// sslmode=disable is expressed via a nil TLSConfig.
	poolCfg, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	poolCfg.ConnConfig.Host = cfg.Host
	poolCfg.ConnConfig.Port = uint16(cfg.Port)
	poolCfg.ConnConfig.User = cfg.User
	poolCfg.ConnConfig.Password = cfg.Password
	poolCfg.ConnConfig.Database = cfg.DBName
	poolCfg.ConnConfig.TLSConfig = nil

	poolCfg.MaxConns = 10
	poolCfg.MinConns = 2
	poolCfg.MaxConnLifetime = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect to db: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return pool, nil
}

type User struct {
	ID           string    `json:"id"`
	Login        string    `json:"login"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Scan struct {
	ID         string         `json:"id"`
	UserID     string         `json:"userId"`
	JobID      string         `json:"jobId"`
	TargetURL  string         `json:"targetUrl"`
	Status     string         `json:"status"`
	ConfigHash string         `json:"configHash,omitempty"`
	CITokenID  *string        `json:"ciTokenId,omitempty"`
	Source     string         `json:"source,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
	UpdatedAt  time.Time      `json:"updatedAt"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
}

type Finding struct {
	ID          string         `json:"id"`
	ScanID      string         `json:"scanId"`
	Severity    string         `json:"severity"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	EndpointPath string        `json:"endpointPath,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	CreatedAt   time.Time      `json:"createdAt"`
}

func CreateUser(ctx context.Context, pool *pgxpool.Pool, login, passwordHash, role string) (*User, error) {
	var user User
	err := pool.QueryRow(ctx,
		"INSERT INTO users (login, password_hash, role) VALUES ($1, $2, $3) RETURNING id, login, role, created_at",
		login, passwordHash, role,
	).Scan(&user.ID, &user.Login, &user.Role, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpsertUser creates a user or updates password/role if login already exists.
func UpsertUser(ctx context.Context, pool *pgxpool.Pool, login, passwordHash, role string) (*User, error) {
	var user User
	err := pool.QueryRow(ctx,
		`INSERT INTO users (login, password_hash, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (login)
		 DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
		 RETURNING id, login, role, created_at`,
		login, passwordHash, role,
	).Scan(&user.ID, &user.Login, &user.Role, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByLogin(ctx context.Context, pool *pgxpool.Pool, login string) (*User, error) {
	var user User
	err := pool.QueryRow(ctx,
		"SELECT id, login, password_hash, role, created_at FROM users WHERE login = $1",
		login,
	).Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Role, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUsers(ctx context.Context, pool *pgxpool.Pool) ([]User, error) {
	rows, err := pool.Query(ctx, "SELECT id, login, role, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Login, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func CreateScan(ctx context.Context, pool *pgxpool.Pool, userID, jobID, targetURL, configHash string) (*Scan, error) {
	return CreateScanWithMeta(ctx, pool, CreateScanParams{
		UserID: userID, JobID: jobID, TargetURL: targetURL, ConfigHash: configHash, Source: "web",
	})
}

func GetScansByUser(ctx context.Context, pool *pgxpool.Pool, userID string) ([]Scan, error) {
	rows, err := pool.Query(ctx,
		`SELECT `+scanSelectCols+` FROM scans s
		 WHERE s.user_id = $1
		    OR s.ci_token_id IN (SELECT id FROM ci_tokens WHERE owner_user_id = $1)
		 ORDER BY s.created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func GetAllScans(ctx context.Context, pool *pgxpool.Pool) ([]Scan, error) {
	rows, err := pool.Query(ctx, `SELECT `+scanSelectCols+` FROM scans ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func UpdateScanStatus(ctx context.Context, pool *pgxpool.Pool, jobID, status string) error {
	_, err := pool.Exec(ctx,
		`UPDATE scans SET status = $1::varchar, updated_at = NOW(), finished_at = CASE WHEN $1 IN ('SUCCEEDED', 'FAILED', 'PARTIAL_SUCCESS', 'CANCELLED') THEN NOW() ELSE NULL END WHERE job_id = $2`,
		status, jobID,
	)
	return err
}

func GetScanByID(ctx context.Context, pool *pgxpool.Pool, id string) (*Scan, error) {
	row := pool.QueryRow(ctx, `SELECT `+scanSelectCols+` FROM scans WHERE id = $1`, id)
	return scanRow(row)
}

func GetScanByJobID(ctx context.Context, pool *pgxpool.Pool, jobID string) (*Scan, error) {
	row := pool.QueryRow(ctx, `SELECT `+scanSelectCols+` FROM scans WHERE job_id = $1`, jobID)
	return scanRow(row)
}

func DeleteScan(ctx context.Context, pool *pgxpool.Pool, jobID string) error {
	_, err := pool.Exec(ctx, "DELETE FROM scans WHERE job_id = $1", jobID)
	return err
}

func GetFindingsByScanID(ctx context.Context, pool *pgxpool.Pool, scanID string) ([]Finding, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, scan_id, severity, name, description, endpoint_path, evidence, created_at
		 FROM findings WHERE scan_id = $1 ORDER BY created_at DESC`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Severity, &f.Name, &f.Description, &f.EndpointPath, &f.Evidence, &f.CreatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ReplaceFindingsForScan deletes existing findings for a scan and inserts the new set.
func ReplaceFindingsForScan(ctx context.Context, pool *pgxpool.Pool, scanID string, items []Finding) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE scan_id = $1`, scanID); err != nil {
		return err
	}
	for _, f := range items {
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (scan_id, severity, name, description, endpoint_path, evidence) VALUES ($1, $2, $3, $4, $5, $6)`,
			scanID, f.Severity, f.Name, f.Description, f.EndpointPath, f.Evidence,
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func DeleteUserByLogin(ctx context.Context, pool *pgxpool.Pool, login string) error {
	_, err := pool.Exec(ctx, "DELETE FROM users WHERE login = $1", login)
	return err
}

// DeleteUserByID removes a user and clears optional references from ci_tokens.
func DeleteUserByID(ctx context.Context, pool *pgxpool.Pool, id string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "UPDATE ci_tokens SET owner_user_id = NULL WHERE owner_user_id = $1", id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "UPDATE ci_tokens SET created_by = NULL WHERE created_by = $1", id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return tx.Commit(ctx)
}
