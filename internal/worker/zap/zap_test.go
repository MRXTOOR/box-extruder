package zap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/model"
)

func TestParseReportJSON(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "minimal-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings, ev, err := ParseReportJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(ev) != 1 {
		t.Fatalf("findings=%d ev=%d", len(findings), len(ev))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Fatal(findings[0].Severity)
	}
	if findings[0].RuleID != "40012" {
		t.Fatal(findings[0].RuleID)
	}
}

func TestParseReportJSON_instances(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "instances-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings, ev, err := ParseReportJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || len(ev) != 2 {
		t.Fatalf("findings=%d ev=%d", len(findings), len(ev))
	}
	if !strings.Contains(findings[0].LocationKey, "example.com/forms/post") {
		t.Fatalf("location: %s", findings[0].LocationKey)
	}
	if !strings.Contains(findings[1].LocationKey, "example.com/login") {
		t.Fatalf("location: %s", findings[1].LocationKey)
	}
}
