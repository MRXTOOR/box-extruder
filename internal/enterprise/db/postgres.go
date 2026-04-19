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
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName)

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

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
	ID         string     `json:"id"`
	UserID     string     `json:"userId"`
	JobID      string     `json:"jobId"`
	TargetURL  string     `json:"targetUrl"`
	Status     string     `json:"status"`
	ConfigHash string     `json:"configHash,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

type Finding struct {
	ID          string         `json:"id"`
	ScanID      string         `json:"scanId"`
	Severity    string         `json:"severity"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
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
	var scan Scan
	err := pool.QueryRow(ctx,
		`INSERT INTO scans (user_id, job_id, target_url, config_hash) 
		 VALUES ($1, $2, $3, $4) 
		 RETURNING id, user_id, job_id, target_url, status, config_hash, created_at, updated_at`,
		userID, jobID, targetURL, configHash,
	).Scan(&scan.ID, &scan.UserID, &scan.JobID, &scan.TargetURL, &scan.Status, &scan.ConfigHash, &scan.CreatedAt, &scan.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

func GetScansByUser(ctx context.Context, pool *pgxpool.Pool, userID string) ([]Scan, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, user_id, job_id, target_url, status, config_hash, created_at, updated_at, finished_at 
		 FROM scans WHERE user_id = $1 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.UserID, &s.JobID, &s.TargetURL, &s.Status, &s.ConfigHash, &s.CreatedAt, &s.UpdatedAt, &s.FinishedAt); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, nil
}

func GetAllScans(ctx context.Context, pool *pgxpool.Pool) ([]Scan, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, user_id, job_id, target_url, status, config_hash, created_at, updated_at, finished_at 
		 FROM scans ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.UserID, &s.JobID, &s.TargetURL, &s.Status, &s.ConfigHash, &s.CreatedAt, &s.UpdatedAt, &s.FinishedAt); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, nil
}

func UpdateScanStatus(ctx context.Context, pool *pgxpool.Pool, jobID, status string) error {
	_, err := pool.Exec(ctx,
		`UPDATE scans SET status = $1::varchar, updated_at = NOW(), finished_at = CASE WHEN $1 IN ('SUCCEEDED', 'FAILED', 'PARTIAL_SUCCESS', 'CANCELLED') THEN NOW() ELSE NULL END WHERE job_id = $2`,
		status, jobID,
	)
	return err
}

func GetScanByID(ctx context.Context, pool *pgxpool.Pool, id string) (*Scan, error) {
	var s Scan
	err := pool.QueryRow(ctx,
		`SELECT id, user_id, job_id, target_url, status, config_hash, created_at, updated_at, finished_at 
		 FROM scans WHERE id = $1`,
		id,
	).Scan(&s.ID, &s.UserID, &s.JobID, &s.TargetURL, &s.Status, &s.ConfigHash, &s.CreatedAt, &s.UpdatedAt, &s.FinishedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func GetScanByJobID(ctx context.Context, pool *pgxpool.Pool, jobID string) (*Scan, error) {
	var s Scan
	err := pool.QueryRow(ctx,
		`SELECT id, user_id, job_id, target_url, status, config_hash, created_at, updated_at, finished_at 
		 FROM scans WHERE job_id = $1`,
		jobID,
	).Scan(&s.ID, &s.UserID, &s.JobID, &s.TargetURL, &s.Status, &s.ConfigHash, &s.CreatedAt, &s.UpdatedAt, &s.FinishedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func DeleteScan(ctx context.Context, pool *pgxpool.Pool, jobID string) error {
	_, err := pool.Exec(ctx, "DELETE FROM scans WHERE job_id = $1", jobID)
	return err
}

func GetFindingsByScanID(ctx context.Context, pool *pgxpool.Pool, scanID string) ([]Finding, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, scan_id, severity, name, description, evidence, created_at 
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
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Severity, &f.Name, &f.Description, &f.Evidence, &f.CreatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func DeleteUserByLogin(ctx context.Context, pool *pgxpool.Pool, login string) error {
	_, err := pool.Exec(ctx, "DELETE FROM users WHERE login = $1", login)
	return err
}
