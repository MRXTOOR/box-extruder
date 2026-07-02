package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/box-extruder/dast/internal/enterprise/auth"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/enterprise/queue"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	DB         db.Config
	Queue      queue.Config
	Auth       auth.Config
	WorkDir    string
	ListenAddr string
	Bootstrap  BootstrapConfig
}

type BootstrapConfig struct {
	Enabled       bool
	AdminLogin    string
	AdminPassword string
	AdminRole     string
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.DB.Host, "db-host", "postgres", "PostgreSQL host")
	flag.IntVar(&cfg.DB.Port, "db-port", 5432, "PostgreSQL port")
	flag.StringVar(&cfg.DB.User, "db-user", "dast", "PostgreSQL user")
	flag.StringVar(&cfg.DB.Password, "db-pass", "dast", "PostgreSQL password")
	flag.StringVar(&cfg.DB.DBName, "db-name", "dast", "PostgreSQL database")

	flag.StringVar(&cfg.Queue.Host, "redis-host", "redis", "Redis host")
	flag.IntVar(&cfg.Queue.Port, "redis-port", 6379, "Redis port")
	flag.StringVar(&cfg.Queue.Password, "redis-pass", "", "Redis password")

	flag.StringVar(&cfg.Auth.Secret, "jwt-secret", envString("JWT_SECRET", ""), "JWT secret key")
	flag.StringVar(&cfg.WorkDir, "work-dir", "/workspace/work", "Work directory")
	flag.StringVar(&cfg.ListenAddr, "listen", ":8080", "Listen address")
	flag.BoolVar(&cfg.Bootstrap.Enabled, "bootstrap-admin-enabled", envBool("BOOTSTRAP_ADMIN_ENABLED", false), "Enable bootstrap admin upsert on startup")
	flag.StringVar(&cfg.Bootstrap.AdminLogin, "bootstrap-admin-login", envString("BOOTSTRAP_ADMIN_LOGIN", "admin"), "Bootstrap admin login")
	flag.StringVar(&cfg.Bootstrap.AdminPassword, "bootstrap-admin-password", envString("BOOTSTRAP_ADMIN_PASSWORD", ""), "Bootstrap admin password")
	flag.StringVar(&cfg.Bootstrap.AdminRole, "bootstrap-admin-role", envString("BOOTSTRAP_ADMIN_ROLE", "admin"), "Bootstrap admin role (admin or specialist)")
	flag.Parse()

	if err := os.MkdirAll(cfg.WorkDir, 0755); err != nil {
		log.Fatalf("Failed to create work dir: %v", err)
	}
	if err := validateJWTSecret(cfg.Auth.Secret); err != nil {
		log.Fatalf("JWT secret configuration error: %v", err)
	}

	ctx := context.Background()

	pool, err := db.Connect(cfg.DB)
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer pool.Close()
	log.Println("Connected to PostgreSQL")

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		log.Fatalf("DB migrations: %v", err)
	}

	if err := ensureBootstrapAdmin(ctx, pool, cfg.Bootstrap); err != nil {
		log.Fatalf("Bootstrap admin: %v", err)
	}

	rdb, err := queue.Connect(cfg.Queue)
	if err != nil {
		log.Fatalf("Redis connect: %v", err)
	}
	defer rdb.Close()
	log.Println("Connected to Redis")

	authManager := auth.NewManager(cfg.Auth)

	handler := NewHandler(pool, rdb, authManager, cfg.WorkDir)

	mux := http.NewServeMux()
	handler.Mount(mux)

	// POST /api/v1/scans runs auth discovery against the target before enqueue;
	// 30s WriteTimeout caused nginx 502 ("upstream prematurely closed connection").
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      180 * time.Second,
	}

	go func() {
		log.Printf("Server listening on %s", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}

type Handler struct {
	pool         *db.Pool
	rdb          *redis.Client
	auth         *auth.Manager
	workDir      string
	loginLimiter *loginAttemptLimiter
}

func NewHandler(pool *db.Pool, rdb *redis.Client, auth *auth.Manager, workDir string) *Handler {
	return &Handler{
		pool:         pool,
		rdb:          rdb,
		auth:         auth,
		workDir:      workDir,
		loginLimiter: newLoginAttemptLimiter(5, 15*time.Minute),
	}
}

func ensureBootstrapAdmin(ctx context.Context, pool *db.Pool, cfg BootstrapConfig) error {
	if !cfg.Enabled {
		log.Println("Bootstrap admin disabled (BOOTSTRAP_ADMIN_ENABLED=false)")
		return nil
	}
	if cfg.AdminLogin == "" {
		return fmt.Errorf("bootstrap admin login is empty")
	}
	if cfg.AdminPassword == "" {
		return fmt.Errorf("bootstrap admin password is empty")
	}
	if cfg.AdminRole != "admin" && cfg.AdminRole != "specialist" {
		return fmt.Errorf("bootstrap admin role must be admin or specialist")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash bootstrap admin password: %w", err)
	}
	u, err := db.UpsertUser(ctx, pool, cfg.AdminLogin, string(hash), cfg.AdminRole)
	if err != nil {
		return fmt.Errorf("upsert bootstrap admin: %w", err)
	}
	log.Printf("Bootstrap admin ready: login=%s role=%s", u.Login, u.Role)
	return nil
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		switch v {
		case "1", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On":
			return true
		case "0", "false", "FALSE", "False", "no", "NO", "No", "off", "OFF", "Off":
			return false
		default:
			return fallback
		}
	}
	return fallback
}

func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", h.handleLogin)
	mux.HandleFunc("GET /api/v1/auth/me", h.authMiddleware(h.handleMe))

	mux.HandleFunc("GET /api/v1/scans", h.authMiddleware(h.handleListScans))
	mux.HandleFunc("POST /api/v1/scans", h.authMiddleware(h.handleCreateScan))
	mux.HandleFunc("GET /api/v1/scans/{id}", h.authMiddleware(h.handleGetScan))
	mux.HandleFunc("GET /api/v1/scans/{id}/findings", h.authMiddleware(h.handleGetScanFindings))
	mux.HandleFunc("GET /api/v1/scans/{id}/findings/counts", h.authMiddleware(h.handleGetScanFindingsCounts))
	mux.HandleFunc("DELETE /api/v1/scans/{id}", h.authMiddleware(h.handleDeleteScan))
	mux.HandleFunc("GET /api/v1/scans/{id}/status", h.authMiddleware(h.handleScanStatus))
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", h.authMiddleware(h.handleCancelScan))
	mux.HandleFunc("POST /api/v1/scans/{id}/restart", h.authMiddleware(h.handleRestartScan))
	mux.HandleFunc("GET /api/v1/scans/{id}/reports", h.authMiddleware(h.handleReports))
	mux.HandleFunc("GET /api/v1/scans/{id}/endpoints", h.authMiddleware(h.handleEndpoints))
	mux.HandleFunc("GET /api/v1/scans/{id}/discovered-urls", h.authMiddleware(h.handleDiscoveredURLs))
	mux.HandleFunc("GET /api/v1/scans/{id}/dump", h.authMiddleware(h.handleScanDump))
	mux.HandleFunc("GET /api/v1/scans/{id}/logs", h.authMiddleware(h.handleScanLogs))
	mux.HandleFunc("POST /api/v1/scans/{id}/ci-metadata", h.authMiddleware(h.handleScanCIMetadata))

	mux.HandleFunc("GET /api/v1/admin/ci-tokens", h.adminOnly(h.handleAdminListCITokens))
	mux.HandleFunc("POST /api/v1/admin/ci-tokens", h.adminOnly(h.handleAdminCreateCIToken))
	mux.HandleFunc("POST /api/v1/admin/ci-tokens/verify", h.adminOnly(h.handleAdminVerifyCIToken))
	mux.HandleFunc("GET /api/v1/admin/ci-tokens/{id}/scans", h.adminOnly(h.handleAdminCITokenScans))
	mux.HandleFunc("GET /api/v1/admin/ci-tokens/{id}", h.adminOnly(h.handleAdminGetCIToken))
	mux.HandleFunc("PATCH /api/v1/admin/ci-tokens/{id}", h.adminOnly(h.handleAdminPatchCIToken))
	mux.HandleFunc("DELETE /api/v1/admin/ci-tokens/{id}", h.adminOnly(h.handleAdminRevokeCIToken))

	mux.HandleFunc("GET /api/v1/admin/users", h.adminOnly(h.handleAdminListUsers))
	mux.HandleFunc("POST /api/v1/admin/users", h.adminOnly(h.handleAdminCreateUser))
	mux.HandleFunc("GET /api/v1/admin/users/{id}", h.adminOnly(h.handleAdminGetUser))
	mux.HandleFunc("PATCH /api/v1/admin/users/{id}", h.adminOnly(h.handleAdminPatchUser))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}", h.adminOnly(h.handleAdminDeleteUser))

	mux.HandleFunc("GET /api/v1/me/ci-tokens", h.authMiddleware(h.handleMeListCITokens))
	mux.HandleFunc("POST /api/v1/me/ci-tokens", h.authMiddleware(h.handleMeCreateCIToken))
	mux.HandleFunc("POST /api/v1/me/ci-tokens/verify", h.authMiddleware(h.handleMeVerifyCIToken))
	mux.HandleFunc("GET /api/v1/me/ci-tokens/{id}/scans", h.authMiddleware(h.handleMeCITokenScans))
	mux.HandleFunc("DELETE /api/v1/me/ci-tokens/{id}", h.authMiddleware(h.handleMeRevokeCIToken))
	mux.HandleFunc("GET /api/v1/me/ci-tokens/{id}", h.authMiddleware(h.handleMeGetCIToken))

	mux.HandleFunc("POST /api/v1/auth/discover", h.adminOnly(h.handleAuthDiscover))

	mux.HandleFunc("GET /api/v1/containers", h.adminOnly(h.handleContainerStatus))
	mux.HandleFunc("GET /api/v1/containers/logs", h.adminOnly(h.handleContainerLogs))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})
}

// contextKey is an unexported type for request-context keys to avoid collisions
// with keys defined in other packages (go vet SA1029).
type contextKey string

const userContextKey contextKey = "user"

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const bearerPrefix = "Bearer "
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(authHeader[len(bearerPrefix):])
		claims, err := h.auth.ValidateToken(token)
		if err != nil {
			claims, ciID, err := h.claimsFromCIToken(r.Context(), token)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			ctx := withAuthContext(r.Context(), claims, ciID, authSourceCIToken)
			next(w, r.WithContext(ctx))
			return
		}
		ctx := withAuthContext(r.Context(), claims, "", authSourceJWT)
		next(w, r.WithContext(ctx))
	}
}

func (h *Handler) claimsFromCIToken(ctx context.Context, secret string) (*auth.Claims, string, error) {
	ciID, err := db.ParseCITokenIDFromSecret(secret)
	if err != nil {
		return nil, "", err
	}
	user, err := db.AuthenticateCIToken(ctx, h.pool, secret)
	if err != nil {
		return nil, "", err
	}
	return &auth.Claims{
		UserID: user.ID,
		Login:  user.Login,
		Role:   user.Role,
	}, ciID, nil
}

func (h *Handler) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return h.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := claimsFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func validateJWTSecret(secret string) error {
	s := strings.TrimSpace(secret)
	if len(s) < 32 {
		return fmt.Errorf("JWT_SECRET/jwt-secret must be at least 32 chars")
	}
	if strings.EqualFold(s, "changeme") {
		return fmt.Errorf("JWT secret must not use default value")
	}
	return nil
}
