package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/box-extruder/dast/internal/enterprise/auth"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/enterprise/queue"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	DB         db.Config
	Queue      queue.Config
	Auth       auth.Config
	WorkDir    string
	ListenAddr string
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

	flag.StringVar(&cfg.Auth.Secret, "jwt-secret", "changeme", "JWT secret key")
	flag.StringVar(&cfg.WorkDir, "work-dir", "/workspace/work", "Work directory")
	flag.StringVar(&cfg.ListenAddr, "listen", ":8080", "Listen address")
	flag.Parse()

	if err := os.MkdirAll(cfg.WorkDir, 0755); err != nil {
		log.Fatalf("Failed to create work dir: %v", err)
	}

	ctx := context.Background()

	pool, err := db.Connect(cfg.DB)
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer pool.Close()
	log.Println("Connected to PostgreSQL")

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

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
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
	pool    *db.Pool
	rdb     *redis.Client
	auth    *auth.Manager
	workDir string
}

func NewHandler(pool *db.Pool, rdb *redis.Client, auth *auth.Manager, workDir string) *Handler {
	return &Handler{pool: pool, rdb: rdb, auth: auth, workDir: workDir}
}

func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", h.handleLogin)
	mux.HandleFunc("GET /api/v1/auth/me", h.authMiddleware(h.handleMe))

	mux.HandleFunc("GET /api/v1/scans", h.authMiddleware(h.handleListScans))
	mux.HandleFunc("POST /api/v1/scans", h.authMiddleware(h.handleCreateScan))
	mux.HandleFunc("GET /api/v1/scans/{id}", h.authMiddleware(h.handleGetScan))
	mux.HandleFunc("DELETE /api/v1/scans/{id}", h.authMiddleware(h.handleDeleteScan))
	mux.HandleFunc("GET /api/v1/scans/{id}/status", h.authMiddleware(h.handleScanStatus))
	mux.HandleFunc("GET /api/v1/scans/{id}/reports", h.handleReports)
	mux.HandleFunc("GET /api/v1/scans/{id}/endpoints", h.handleEndpoints)

	mux.HandleFunc("POST /api/v1/auth/discover", h.handleAuthDiscover)

	mux.HandleFunc("GET /api/v1/containers", h.authMiddleware(h.handleContainerStatus))
	mux.HandleFunc("GET /api/v1/containers/logs", h.authMiddleware(h.handleContainerLogs))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})
}

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := authHeader[7:]
		claims, err := h.auth.ValidateToken(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user", claims)
		next(w, r.WithContext(ctx))
	}
}
