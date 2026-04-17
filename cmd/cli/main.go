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
	if len(parts) == 2 {
		return kv{key: parts[0][2:], value: parts[1]}
	}
	return kv{}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("DAST CLI - User management")
		fmt.Println("\nUsage:")
		fmt.Println("  dast-cli user add --login=<login> --password=<password> --role=<role>")
		fmt.Println("  dast-cli user list")
		fmt.Println("  dast-cli user delete --login=<login>")
		fmt.Println("\nRoles: admin, specialist")
		os.Exit(1)
	}

	host := "localhost"
	port := 5432
	user := "dast"
	pass := "dast"
	dbname := "dast"

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--db-host" && i+1 < len(os.Args) {
			host = os.Args[i+1]
			i++
		} else if arg == "--db-port" && i+1 < len(os.Args) {
			fmt.Sscanf(os.Args[i+1], "%d", &port)
			i++
		} else if arg == "--db-user" && i+1 < len(os.Args) {
			user = os.Args[i+1]
			i++
		} else if arg == "--db-pass" && i+1 < len(os.Args) {
			pass = os.Args[i+1]
			i++
		} else if arg == "--db-name" && i+1 < len(os.Args) {
			dbname = os.Args[i+1]
			i++
		}
	}

	cfg := db.Config{
		Host:     host,
		Port:     port,
		User:     user,
		Password: pass,
		DBName:   dbname,
	}

	pool, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	if os.Args[1] == "user" && os.Args[2] == "add" {
		var login, password, role string
		for i := 3; i < len(os.Args); i++ {
			arg := os.Args[i]
			parts := splitArg(arg)
			if parts.key == "login" {
				login = parts.value
			} else if parts.key == "password" {
				password = parts.value
			} else if parts.key == "role" {
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
		_, err = db.CreateUser(ctx, pool, login, string(hash), role)
		if err != nil {
			log.Fatalf("Create user: %v", err)
		}
		fmt.Printf("User %s created with role %s\n", login, role)
		return
	}

	if os.Args[1] == "user" && os.Args[2] == "list" {
		users, err := db.GetUsers(ctx, pool)
		if err != nil {
			log.Fatalf("List users: %v", err)
		}
		fmt.Println("ID                                    | Login   | Role        | Created")
		fmt.Println("--------------------------------------|---------|-------------|----------------")
		for _, u := range users {
			fmt.Printf("%s | %-7s | %-11s | %s\n", u.ID, u.Login, u.Role, u.CreatedAt.Format("2006-01-02 15:04"))
		}
		return
	}

	if os.Args[1] == "user" && os.Args[2] == "delete" {
		var login string
		for i := 3; i < len(os.Args); i++ {
			arg := os.Args[i]
			if len(arg) > 7 && arg[:7] == "--login=" {
				login = arg[7:]
			}
		}
		if login == "" {
			log.Fatal("--login required")
		}
		err := db.DeleteUserByLogin(ctx, pool, login)
		if err != nil {
			log.Fatalf("Delete user: %v", err)
		}
		fmt.Printf("User %s deleted\n", login)
		return
	}

	fmt.Println("Unknown command")
	os.Exit(1)
}
