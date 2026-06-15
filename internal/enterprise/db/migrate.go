package db

import (
	"context"
	"embed"
	"fmt"
	"log"
	"path"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationSQL embed.FS

const migrationLockID int64 = 7274829

// ApplyMigrations runs pending SQL migrations embedded in the binary.
// Safe to call from server and worker on startup (uses an advisory lock).
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("migration lock: %w", err)
	}
	defer pool.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrationLockID) //nolint:errcheck

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		return fmt.Errorf("schema_migrations table: %w", err)
	}

	entries, err := migrationSQL.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".sql") {
			continue
		}
		version := ent.Name()
		var applied bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`,
			version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied {
			continue
		}

		body, err := migrationSQL.ReadFile(path.Join("migrations", version))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		sql := strings.TrimSpace(string(body))
		if sql == "" {
			continue
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`,
			version,
		); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
		log.Printf("Applied DB migration %s", version)
	}
	return nil
}
