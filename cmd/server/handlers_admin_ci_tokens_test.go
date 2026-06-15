package main

import (
	"testing"

	"github.com/box-extruder/dast/internal/enterprise/db"
)

func TestParseCITokenIDFromSecret(t *testing.T) {
	id := "550e8400-e29b-41d4-a716-446655440000"
	secret := db.FormatCITokenSecret(id)
	got, err := db.ParseCITokenIDFromSecret(secret)
	if err != nil || got != id {
		t.Fatalf("ParseCITokenIDFromSecret: got %q err=%v", got, err)
	}
}

func TestCITokenNamePattern(t *testing.T) {
	for _, name := range []string{"consumer-api", "team1", "a1"} {
		if !ciTokenNameRe.MatchString(name) {
			t.Fatalf("expected valid name %q", name)
		}
	}
	if ciTokenNameRe.MatchString("Bad_Name") {
		t.Fatal("expected invalid name rejected")
	}
}
