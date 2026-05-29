package main

import (
	"testing"

	"github.com/box-extruder/dast/internal/enterprise/db"
)

func TestEnrichFindingEndpoint(t *testing.T) {
	full := enrichFindingEndpoint(db.Finding{
		EndpointPath: "/api/v1/users",
		Evidence: map[string]any{
			"locationKey": "GET https://example.com/api/v1/users?limit=10",
		},
	})
	want := "https://example.com/api/v1/users?limit=10"
	if full.EndpointPath != want {
		t.Fatalf("got %q, want %q", full.EndpointPath, want)
	}
}
