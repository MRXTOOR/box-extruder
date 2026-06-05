package db

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestFormatCITokenSecret(t *testing.T) {
	s := FormatCITokenSecret("550e8400-e29b-41d4-a716-446655440000")
	if s != "dast_550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("unexpected secret format: %s", s)
	}
}

func TestCITokenBcryptRoundTrip(t *testing.T) {
	secret := FormatCITokenSecret("550e8400-e29b-41d4-a716-446655440000")
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("dast_wrong")); err == nil {
		t.Fatal("expected mismatch")
	}
}
