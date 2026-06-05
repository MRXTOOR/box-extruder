package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/enterprise/db"
	"golang.org/x/crypto/bcrypt"
)

func handleCIToken(args []string) {
	if len(args) < 1 {
		ciTokenUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "create":
		pool, err := db.Connect(parseDBConfig(os.Args))
		if err != nil {
			log.Fatalf("DB connect: %v", err)
		}
		defer pool.Close()
		ciTokenCreate(context.Background(), pool, args[1:])
	case "list":
		pool, err := db.Connect(parseDBConfig(os.Args))
		if err != nil {
			log.Fatalf("DB connect: %v", err)
		}
		defer pool.Close()
		ciTokenList(context.Background(), pool, args[1:])
	case "revoke":
		pool, err := db.Connect(parseDBConfig(os.Args))
		if err != nil {
			log.Fatalf("DB connect: %v", err)
		}
		defer pool.Close()
		ciTokenRevoke(context.Background(), pool, args[1:])
	case "verify":
		ciTokenVerify(args[1:])
	default:
		ciTokenUsage()
		os.Exit(1)
	}
}

func handleCISetup(args []string) {
	pool, err := db.Connect(parseDBConfig(os.Args))
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer pool.Close()
	ciSetup(context.Background(), pool, args)
}

func ciTokenUsage() {
	fmt.Println("CI token commands:")
	fmt.Println("  dast-cli ci-token create --user=<login> --name=<project> [--expires-days=N]")
	fmt.Println("  dast-cli ci-token list [--user=<login>]")
	fmt.Println("  dast-cli ci-token revoke --id=<uuid>")
	fmt.Println("  dast-cli ci-token verify --api-url=<url> --token=<secret> [--insecure]")
}

func ciTokenCreate(ctx context.Context, pool *db.Pool, args []string) {
	var userLogin, name string
	var expiresDays int
	for _, arg := range args {
		switch parts := splitArg(arg); parts.key {
		case "user":
			userLogin = parts.value
		case "name":
			name = parts.value
		case "expires-days":
			fmt.Sscanf(parts.value, "%d", &expiresDays)
		}
	}
	if userLogin == "" {
		log.Fatal("--user required")
	}
	if name == "" {
		log.Fatal("--name required")
	}
	user, err := db.GetUserByLogin(ctx, pool, userLogin)
	if err != nil {
		log.Fatalf("User %q: %v", userLogin, err)
	}
	var expiresAt *time.Time
	if expiresDays > 0 {
		t := time.Now().UTC().Add(time.Duration(expiresDays) * 24 * time.Hour)
		expiresAt = &t
	}
	secret, token, err := db.CreateCIToken(ctx, pool, user.ID, name, expiresAt)
	if err != nil {
		log.Fatalf("Create token: %v", err)
	}
	fmt.Println("CI token created (save the secret — it is shown only once):")
	fmt.Printf("  id:     %s\n", token.ID)
	fmt.Printf("  user:   %s\n", user.Login)
	fmt.Printf("  name:   %s\n", token.Name)
	fmt.Printf("  secret: %s\n", secret)
	fmt.Println()
	fmt.Println("Jenkins: add Secret text credential, e.g. dast-ci-" + name)
	fmt.Println("  environment { DAST_CI_TOKEN = credentials('dast-ci-" + name + "') }")
}

func ciTokenList(ctx context.Context, pool *db.Pool, args []string) {
	var userLogin string
	for _, arg := range args {
		if parts := splitArg(arg); parts.key == "user" {
			userLogin = parts.value
		}
	}
	tokens, err := db.ListCITokens(ctx, pool, userLogin)
	if err != nil {
		log.Fatalf("List tokens: %v", err)
	}
	fmt.Println("ID                                    | User ID                               | Name                 | Created             | Last used           | Status")
	fmt.Println("--------------------------------------|---------------------------------------|----------------------|---------------------|---------------------|--------")
	for _, t := range tokens {
		status := "active"
		if t.RevokedAt != nil {
			status = "revoked"
		} else if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
			status = "expired"
		}
		last := "-"
		if t.LastUsedAt != nil {
			last = t.LastUsedAt.Format("2006-01-02 15:04")
		}
		fmt.Printf("%s | %s | %-20s | %s | %s | %s\n",
			t.ID, t.UserID, truncate(nameCol(t.Name, 20), 20), t.CreatedAt.Format("2006-01-02 15:04"), last, status)
	}
}

func nameCol(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func ciTokenRevoke(ctx context.Context, pool *db.Pool, args []string) {
	var id string
	for _, arg := range args {
		if parts := splitArg(arg); parts.key == "id" {
			id = parts.value
		}
	}
	if id == "" {
		log.Fatal("--id required")
	}
	if err := db.RevokeCIToken(ctx, pool, id); err != nil {
		log.Fatalf("Revoke: %v", err)
	}
	fmt.Printf("CI token %s revoked\n", id)
}

func ciTokenVerify(args []string) {
	var apiURL, token string
	insecure := false
	for _, arg := range args {
		switch parts := splitArg(arg); parts.key {
		case "api-url":
			apiURL = strings.TrimRight(parts.value, "/")
		case "token":
			token = parts.value
		case "insecure":
			insecure = parts.value == "true" || parts.value == "1"
		}
	}
	if apiURL == "" {
		log.Fatal("--api-url required")
	}
	if token == "" {
		log.Fatal("--token required")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicit CI verify flag
		}
	}
	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/v1/auth/me", nil)
	if err != nil {
		log.Fatalf("Request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("HTTP: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("verify failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var me map[string]any
	if err := json.Unmarshal(body, &me); err != nil {
		log.Fatalf("parse response: %v", err)
	}
	fmt.Println("CI token verified successfully:")
	fmt.Printf("  login: %v\n", me["login"])
	fmt.Printf("  role:  %v\n", me["role"])
	fmt.Printf("  id:    %v\n", me["id"])
}

func ciSetup(ctx context.Context, pool *db.Pool, args []string) {
	var name, userLogin, role, apiURL string
	verify := false
	insecure := false
	var userPassword string
	expiresDays := 0

	for _, arg := range args {
		if arg == "--verify" {
			verify = true
			continue
		}
		parts := splitArg(arg)
		switch parts.key {
		case "name":
			name = parts.value
		case "user":
			userLogin = parts.value
		case "role":
			role = parts.value
		case "password":
			userPassword = parts.value
		case "api-url":
			apiURL = strings.TrimRight(parts.value, "/")
		case "verify":
			verify = parts.value != "false" && parts.value != "0"
		case "insecure":
			insecure = parts.value == "true" || parts.value == "1"
		case "expires-days":
			fmt.Sscanf(parts.value, "%d", &expiresDays)
		}
	}
	if name == "" {
		log.Fatal("--name required")
	}
	if userLogin == "" {
		userLogin = "ci-" + name
	}
	if role == "" {
		role = "specialist"
	}
	if role != "admin" && role != "specialist" {
		log.Fatal("role must be admin or specialist")
	}

	user, err := db.GetUserByLogin(ctx, pool, userLogin)
	if err != nil {
		if userPassword == "" {
			log.Fatalf("user %q not found; pass --password to create", userLogin)
		}
		hash, err := bcryptGenerate(userPassword)
		if err != nil {
			log.Fatalf("hash password: %v", err)
		}
		user, err = db.CreateUser(ctx, pool, userLogin, hash, role)
		if err != nil {
			log.Fatalf("create user: %v", err)
		}
		fmt.Printf("Created user %s (role %s)\n", user.Login, user.Role)
	}

	var expiresAt *time.Time
	if expiresDays > 0 {
		t := time.Now().UTC().Add(time.Duration(expiresDays) * 24 * time.Hour)
		expiresAt = &t
	}
	secret, token, err := db.CreateCIToken(ctx, pool, user.ID, name, expiresAt)
	if err != nil {
		log.Fatalf("create token: %v", err)
	}

	fmt.Println()
	fmt.Println("=== CI handoff ===")
	fmt.Printf("jenkins_credential_id: dast-ci-%s\n", name)
	fmt.Printf("ci_token: %s\n", secret)
	fmt.Printf("token_id: %s\n", token.ID)
	fmt.Printf("service_user: %s\n", user.Login)
	fmt.Println()
	fmt.Println("Pipeline snippet:")
	fmt.Printf("  apiTokenCredentialId: 'dast-ci-%s'\n", name)

	if verify {
		if apiURL == "" {
			log.Fatal("--api-url required with --verify")
		}
		fmt.Println()
		fmt.Println("Verifying token against API...")
		ciTokenVerify([]string{"--api-url=" + apiURL, "--token=" + secret, fmt.Sprintf("--insecure=%v", insecure)})
	}
}

func bcryptGenerate(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
