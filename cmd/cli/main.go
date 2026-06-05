package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/box-extruder/dast/internal/enterprise/db"
	"golang.org/x/crypto/bcrypt"
)

type kv struct {
	key   string
	value string
}

func splitArg(arg string) kv {
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) == 2 && strings.HasPrefix(parts[0], "--") {
		return kv{key: parts[0][2:], value: parts[1]}
	}
	return kv{}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ci-token":
		handleCIToken(os.Args[2:])
	case "ci":
		if len(os.Args) < 3 || os.Args[2] != "setup" {
			fmt.Println("Unknown ci command; use: dast-cli ci setup ...")
			os.Exit(1)
		}
		handleCISetup(os.Args[3:])
	case "user":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		pool, err := db.Connect(parseDBConfig(os.Args))
		if err != nil {
			log.Fatalf("DB connect: %v", err)
		}
		defer pool.Close()
		ctx := context.Background()
		switch os.Args[2] {
		case "add":
			userAdd(ctx, pool, os.Args[3:])
		case "list":
			userList(ctx, pool)
		case "delete":
			userDelete(ctx, pool, os.Args[3:])
		default:
			fmt.Println("Unknown user command")
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command")
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("DAST CLI")
	fmt.Println("\nUser management:")
	fmt.Println("  dast-cli user add --login=<login> --password=<password> --role=<role>")
	fmt.Println("  dast-cli user list")
	fmt.Println("  dast-cli user delete --login=<login>")
	fmt.Println("\nCI tokens (Jenkins, no Web UI):")
	fmt.Println("  dast-cli ci-token create --user=<login> --name=<project> [--expires-days=N]")
	fmt.Println("  dast-cli ci-token list [--user=<login>]")
	fmt.Println("  dast-cli ci-token revoke --id=<uuid>")
	fmt.Println("  dast-cli ci-token verify --api-url=<url> --token=<secret> [--insecure=true]")
	fmt.Println("  dast-cli ci setup --name=<project> [--user=ci-<project>] [--password=...] [--role=specialist]")
	fmt.Println("                  [--api-url=<url>] [--verify] [--insecure=true] [--expires-days=N]")
	fmt.Println("\nDB flags: --db-host --db-port --db-user --db-pass --db-name")
	fmt.Println("Roles: admin, specialist")
}

func parseDBConfig(args []string) db.Config {
	cfg := db.Config{Host: "localhost", Port: 5432, User: "dast", Password: "dast", DBName: "dast"}
	for i := 1; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--db-host":
			cfg.Host = args[i+1]
			i++
		case "--db-port":
			fmt.Sscanf(args[i+1], "%d", &cfg.Port)
			i++
		case "--db-user":
			cfg.User = args[i+1]
			i++
		case "--db-pass":
			cfg.Password = args[i+1]
			i++
		case "--db-name":
			cfg.DBName = args[i+1]
			i++
		}
	}
	return cfg
}

func userAdd(ctx context.Context, pool *db.Pool, args []string) {
	var login, password, role string
	for _, arg := range args {
		switch parts := splitArg(arg); parts.key {
		case "login":
			login = parts.value
		case "password":
			password = parts.value
		case "role":
			role = parts.value
		}
	}
	if login == "" {
		log.Fatal("--login required")
	}
	if password == "" {
		log.Fatal("--password required")
	}
	if role == "" {
		role = "specialist"
	}
	if role != "admin" && role != "specialist" {
		log.Fatal("role must be admin or specialist")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Hash password: %v", err)
	}
	if _, err := db.CreateUser(ctx, pool, login, string(hash), role); err != nil {
		log.Fatalf("Create user: %v", err)
	}
	fmt.Printf("User %s created with role %s\n", login, role)
}

func userList(ctx context.Context, pool *db.Pool) {
	users, err := db.GetUsers(ctx, pool)
	if err != nil {
		log.Fatalf("List users: %v", err)
	}
	fmt.Println("ID                                    | Login   | Role        | Created")
	fmt.Println("--------------------------------------|---------|-------------|----------------")
	for _, u := range users {
		fmt.Printf("%s | %-7s | %-11s | %s\n", u.ID, u.Login, u.Role, u.CreatedAt.Format("2006-01-02 15:04"))
	}
}

func userDelete(ctx context.Context, pool *db.Pool, args []string) {
	var login string
	for _, arg := range args {
		if parts := splitArg(arg); parts.key == "login" {
			login = parts.value
		}
	}
	if login == "" {
		log.Fatal("--login required")
	}
	if err := db.DeleteUserByLogin(ctx, pool, login); err != nil {
		log.Fatalf("Delete user: %v", err)
	}
	fmt.Printf("User %s deleted\n", login)
}
