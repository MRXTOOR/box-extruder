package main

import (
	"testing"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
)

func TestFindingsToDBRows_FillsFullEndpointURL(t *testing.T) {
	rows := findingsToDBRows("scan-1", []model.Finding{
		{
			FindingID:    "f-1",
			Severity:     model.SeverityHigh,
			Title:        "XSS",
			Description:  "desc",
			LocationKey:  "GET https://example.com/app/profile?tab=security",
			EvidenceRefs: []string{"e-1"},
		},
	})
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	want := "https://example.com/app/profile?tab=security"
	if rows[0].EndpointPath != want {
		t.Fatalf("unexpected endpoint path %q, want %q", rows[0].EndpointPath, want)
	}
}

func TestEndpointURLFromLocationKey(t *testing.T) {
	got := noise.EndpointURLFromLocationKey("GET https://example.com/api/v1/users?limit=10")
	want := "https://example.com/api/v1/users?limit=10"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
