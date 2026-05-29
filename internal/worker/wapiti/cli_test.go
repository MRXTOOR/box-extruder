package wapiti

import (
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

func TestBuildAuthArgs_MapsCookieAndHeaders(t *testing.T) {
	dir := t.TempDir()
	args, err := buildAuthArgs(map[string]string{
		"Authorization": "Bearer token",
		"Cookie":        "session=abc; csrftoken=xyz",
		"X-Tenant":      "demo",
	}, dir)
	if err != nil {
		t.Fatalf("buildAuthArgs: %v", err)
	}
	hasCookie := false
	hasAuth := false
	hasTenant := false
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" && i+1 < len(args) && strings.HasSuffix(args[i+1], "wapiti-cookies.json") {
			hasCookie = true
		}
		if args[i] == "-H" && i+1 < len(args) && args[i+1] == "Authorization: Bearer token" {
			hasAuth = true
		}
		if args[i] == "-H" && i+1 < len(args) && args[i+1] == "X-Tenant: demo" {
			hasTenant = true
		}
	}
	if !hasCookie {
		t.Fatalf("expected -c cookie file argument, got: %v", args)
	}
	if !hasAuth || !hasTenant {
		t.Fatalf("expected custom headers in args, got: %v", args)
	}
}

func TestNormalizeScanForce_BackwardCompatibleValues(t *testing.T) {
	cases := map[string]string{
		"low":        "polite",
		"medium":     "normal",
		"high":       "aggressive",
		"normal":     "normal",
		"aggressive": "aggressive",
		"":           "",
		"unknown":    "",
	}
	for in, want := range cases {
		if got := normalizeScanForce(in); got != want {
			t.Fatalf("normalizeScanForce(%q): want %q, got %q", in, want, got)
		}
	}
}

func TestParseJSONReport_Wapiti304NumericLevel(t *testing.T) {
	raw := []byte(`{
		"vulnerabilities": {
			"Content Security Policy Configuration": [{
				"method": "GET",
				"path": "/",
				"info": "CSP is not set",
				"level": 1,
				"parameter": ""
			}],
			"HTTP Secure Headers": [{
				"method": "GET",
				"path": "/api",
				"info": "X-Frame-Options is not set",
				"level": 2,
				"parameter": ""
			}]
		}
	}`)
	findings, evidence, err := parseJSONReport(raw, "https://example.com", "ctx-1", config.DedupeConfig{})
	if err != nil {
		t.Fatalf("parseJSONReport: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence items, got %d", len(evidence))
	}
	if findings[0].Severity != model.SeverityLow {
		t.Fatalf("level 1 should map to LOW, got %s", findings[0].Severity)
	}
	if findings[1].Severity != model.SeverityMedium {
		t.Fatalf("level 2 should map to MEDIUM, got %s", findings[1].Severity)
	}
	if findings[0].LocationKey == "" {
		t.Fatal("expected location key")
	}
}
