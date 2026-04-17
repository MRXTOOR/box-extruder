package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndValidateToken(t *testing.T) {
	manager := NewManager(Config{Secret: "test-secret-key"})

	token, err := manager.GenerateToken("user-123", "testuser", "specialist")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == "" {
		t.Fatal("token should not be empty")
	}

	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.UserID != "user-123" {
		t.Errorf("expected userID 'user-123', got '%s'", claims.UserID)
	}
	if claims.Login != "testuser" {
		t.Errorf("expected login 'testuser', got '%s'", claims.Login)
	}
	if claims.Role != "specialist" {
		t.Errorf("expected role 'specialist', got '%s'", claims.Role)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	manager := NewManager(Config{Secret: "test-secret-key"})

	_, err := manager.ValidateToken("invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	manager1 := NewManager(Config{Secret: "secret-1"})
	manager2 := NewManager(Config{Secret: "secret-2"})

	token, _ := manager1.GenerateToken("user-123", "testuser", "specialist")

	_, err := manager2.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for token with different secret")
	}
}

func TestClaims_Expiration(t *testing.T) {
	manager := NewManager(Config{Secret: "test-secret"})

	claims := Claims{
		UserID: "user-123",
		Login:  "testuser",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(manager.SecretKey)

	_, err := manager.ValidateToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestNewManager_DefaultSecret(t *testing.T) {
	manager := NewManager(Config{})

	if len(manager.SecretKey) == 0 {
		t.Fatal("secret key should not be empty when not provided")
	}
}
