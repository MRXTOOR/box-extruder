package zap

import (
	"testing"

	"github.com/box-extruder/dast/internal/config"
)

func TestParseURLExportData(t *testing.T) {
	data := []byte("https://example.com/\nhttps://example.com/app?q=1\n# comment\n\n")
	f, e, err := ParseURLExportData(data, "ctx", config.DedupeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 || len(e) != 2 {
		t.Fatalf("want 2 findings, got f=%d e=%d", len(f), len(e))
	}
	if f[0].RuleID != "zap:discovered-url" {
		t.Fatalf("rule: %s", f[0].RuleID)
	}
}

func TestDedupeSeedURLs(t *testing.T) {
	got := dedupeSeedURLs([]string{"https://a/", "https://a/", "https://b/"})
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}
