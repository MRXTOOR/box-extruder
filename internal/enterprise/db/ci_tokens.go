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

var (
	ErrCITokenNotFound = errors.New("ci token not found")
	ErrCITokenRevoked  = errors.New("ci token revoked")
	ErrCITokenExpired  = errors.New("ci token expired")
)

// CIToken is a long-lived credential for CI/CD (Jenkins) without Web UI login.
type CIToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"userId"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

const ciTokenPrefix = "dast_"

// FormatCITokenSecret builds the bearer secret shown once at creation (dast_<uuid>).
func FormatCITokenSecret(id string) string {
	return ciTokenPrefix + id
}

// CreateCIToken inserts a token row and returns the plaintext secret (shown once).
func CreateCIToken(ctx context.Context, pool *pgxpool.Pool, userID, name string, expiresAt *time.Time) (secret string, token *CIToken, err error) {
	id := uuid.New().String()
	secret = FormatCITokenSecret(id)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	var t CIToken
	err = pool.QueryRow(ctx,
		`INSERT INTO ci_tokens (id, user_id, name, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, name, created_at, last_used_at, revoked_at, expires_at`,
		id, userID, name, string(hash), expiresAt,
	).Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.ExpiresAt)
	if err != nil {
		return "", nil, err
	}
	return secret, &t, nil
}

func GetCITokenByID(ctx context.Context, pool *pgxpool.Pool, id string) (*CIToken, string, error) {
	var t CIToken
	var hash string
	err := pool.QueryRow(ctx,
		`SELECT id, user_id, name, token_hash, created_at, last_used_at, revoked_at, expires_at
		 FROM ci_tokens WHERE id = $1`,
		id,
	).Scan(&t.ID, &t.UserID, &t.Name, &hash, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrCITokenNotFound
		}
		return nil, "", err
	}
	return &t, hash, nil
}

// AuthenticateCIToken validates secret dast_<uuid> and returns the owning user.
func AuthenticateCIToken(ctx context.Context, pool *pgxpool.Pool, secret string) (*User, error) {
	if !strings.HasPrefix(secret, ciTokenPrefix) {
		return nil, ErrCITokenNotFound
	}
	id := strings.TrimSpace(secret[len(ciTokenPrefix):])
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrCITokenNotFound
	}

	t, hash, err := GetCITokenByID(ctx, pool, id)
	if err != nil {
		return nil, err
	}
	if t.RevokedAt != nil {
		return nil, ErrCITokenRevoked
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, ErrCITokenExpired
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)); err != nil {
		return nil, ErrCITokenNotFound
	}

	user, err := GetUserByID(ctx, pool, t.UserID)
	if err != nil {
		return nil, err
	}

	_, _ = pool.Exec(ctx, `UPDATE ci_tokens SET last_used_at = NOW() WHERE id = $1`, id)
	return user, nil
}

func ListCITokens(ctx context.Context, pool *pgxpool.Pool, userLogin string) ([]CIToken, error) {
	var rows pgx.Rows
	var err error
	if userLogin != "" {
		rows, err = pool.Query(ctx,
			`SELECT t.id, t.user_id, t.name, t.created_at, t.last_used_at, t.revoked_at, t.expires_at
			 FROM ci_tokens t JOIN users u ON u.id = t.user_id
			 WHERE u.login = $1 ORDER BY t.created_at DESC`,
			userLogin,
		)
	} else {
		rows, err = pool.Query(ctx,
			`SELECT id, user_id, name, created_at, last_used_at, revoked_at, expires_at
			 FROM ci_tokens ORDER BY created_at DESC`,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CIToken
	for rows.Next() {
		var t CIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func RevokeCIToken(ctx context.Context, pool *pgxpool.Pool, id string) error {
	tag, err := pool.Exec(ctx,
		`UPDATE ci_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrCITokenNotFound, id)
	}
	return nil
}

func GetUserByID(ctx context.Context, pool *pgxpool.Pool, id string) (*User, error) {
	var user User
	err := pool.QueryRow(ctx,
		`SELECT id, login, password_hash, role, created_at FROM users WHERE id = $1`,
		id,
	).Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Role, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}
