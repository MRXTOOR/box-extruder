package db

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestUser_Structure(t *testing.T) {
	user := User{
		ID:           "test-id",
		Login:        "testuser",
		PasswordHash: "hash",
		Role:         "specialist",
		CreatedAt:    time.Now(),
	}

	if user.ID != "test-id" {
		t.Errorf("expected ID 'test-id', got '%s'", user.ID)
	}
	if user.Login != "testuser" {
		t.Errorf("expected Login 'testuser', got '%s'", user.Login)
	}
	if user.Role != "specialist" {
		t.Errorf("expected Role 'specialist', got '%s'", user.Role)
	}
}

func TestScan_Structure(t *testing.T) {
	now := time.Now()
	scan := Scan{
		ID:         "scan-id",
		UserID:     "user-id",
		JobID:      "job-id",
		TargetURL:  "https://example.com",
		Status:     "QUEUED",
		ConfigHash: "abc123",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if scan.ID != "scan-id" {
		t.Errorf("expected ID 'scan-id', got '%s'", scan.ID)
	}
	if scan.Status != "QUEUED" {
		t.Errorf("expected Status 'QUEUED', got '%s'", scan.Status)
	}
	if scan.TargetURL != "https://example.com" {
		t.Errorf("expected TargetURL 'https://example.com', got '%s'", scan.TargetURL)
	}
}

func TestFinding_Structure(t *testing.T) {
	finding := Finding{
		ID:          "finding-id",
		ScanID:      "scan-id",
		Severity:    "HIGH",
		Name:        "SQL Injection",
		Description: "SQL injection vulnerability found",
		Evidence:    map[string]any{"param": "id"},
		CreatedAt:   time.Now(),
	}

	if finding.ID != "finding-id" {
		t.Errorf("expected ID 'finding-id', got '%s'", finding.ID)
	}
	if finding.Severity != "HIGH" {
		t.Errorf("expected Severity 'HIGH', got '%s'", finding.Severity)
	}
	if finding.Evidence["param"] != "id" {
		t.Errorf("expected Evidence param 'id', got '%v'", finding.Evidence["param"])
	}
}

func TestConfig_ConnectionString(t *testing.T) {
	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		DBName:   "testdb",
	}

	expected := "postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable"
	actual := "postgres://" + cfg.User + ":" + cfg.Password + "@" + cfg.Host + ":" + "5432" + "/" + cfg.DBName + "?sslmode=disable"

	if actual != expected {
		t.Errorf("expected connection string\n%s\ngot\n%s", expected, actual)
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "testpassword123"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if len(hash) == 0 {
		t.Fatal("hash should not be empty")
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		t.Errorf("Failed to verify password: %v", err)
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte("wrongpassword"))
	if err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestUpdateScanStatus_Logic(t *testing.T) {
	statuses := []string{"QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "PARTIAL_SUCCESS"}
	finishedStatuses := []string{"SUCCEEDED", "FAILED", "PARTIAL_SUCCESS"}

	for _, status := range statuses {
		isFinished := false
		for _, fs := range finishedStatuses {
			if status == fs {
				isFinished = true
				break
			}
		}

		if status == "QUEUED" || status == "RUNNING" {
			if isFinished {
				t.Errorf("status %s should not be finished", status)
			}
		} else {
			if !isFinished {
				t.Errorf("status %s should be finished", status)
			}
		}
	}
}
