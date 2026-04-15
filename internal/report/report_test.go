package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestRenderMarkdown_includesFindingsBySeverity(t *testing.T) {
	findings := []model.Finding{
		{
			FindingID:       "f1",
			RuleID:          "sql-injection",
			Severity:        model.SeverityCritical,
			LifecycleStatus: model.LifecycleDetected,
			Title:           "SQL Injection",
			LocationKey:     "https://x.test/api/users?id=1",
		},
		{
			FindingID:       "f2",
			RuleID:          "xss",
			Severity:        model.SeverityHigh,
			LifecycleStatus: model.LifecycleConfirmed,
			Title:           "Cross-Site Scripting",
			LocationKey:     "https://x.test/search?q=test",
		},
	}
	out := RenderMarkdown("Test Scan", "https://x.test", "Fast", time.Time{}, time.Time{}, findings, nil, false, "low", nil, nil)
	s := string(out)
	if !strings.Contains(s, "DAST Security Report") {
		t.Fatal("missing header")
	}
	if !strings.Contains(s, "CRITICAL") {
		t.Fatal("missing CRITICAL severity")
	}
	if !strings.Contains(s, "HIGH") {
		t.Fatal("missing HIGH severity")
	}
	if !strings.Contains(s, "SQL Injection") {
		t.Fatal("missing finding title")
	}
}

func TestRenderMarkdown_scannedEndpoints(t *testing.T) {
	endpoints := []string{
		"https://x.test/",
		"https://x.test/about",
		"https://x.test/contact",
	}
	findings := []model.Finding{}
	out := RenderMarkdown("Test", "https://x.test", "Fast", time.Time{}, time.Time{}, findings, nil, false, "low", nil, endpoints)
	s := string(out)
	if !strings.Contains(s, "Просканированные эндпоинты") {
		t.Fatal("missing endpoints section")
	}
	if !strings.Contains(s, "3") {
		t.Fatal("missing endpoint count")
	}
	if !strings.Contains(s, "https://x.test/about") {
		t.Fatal("missing endpoint URL")
	}
}

func TestRenderMarkdown_noFindings(t *testing.T) {
	out := RenderMarkdown("Clean Scan", "https://x.test", "Fast", time.Time{}, time.Time{}, nil, nil, false, "low", nil, nil)
	s := string(out)
	if !strings.Contains(s, "DAST Security Report") {
		t.Fatal("missing header")
	}
	if !strings.Contains(s, "0") {
		t.Fatal("should show zero findings")
	}
}

func TestStatusEmoji(t *testing.T) {
	tests := []struct {
		status   model.LifecycleStatus
		contains string
	}{
		{model.LifecycleConfirmed, "Confirmed"},
		{model.LifecycleFalsePositiveSuppressed, "Suppressed"},
		{model.LifecycleDetected, "Detected"},
	}
	for _, tt := range tests {
		result := statusEmoji(tt.status)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("statusEmoji(%s) = %s, want containing %s", tt.status, result, tt.contains)
		}
	}
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

func TestWriteReportHTMLFallback(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "report.md")
	if err := os.WriteFile(md, []byte("# T\n|a|b|\n<script>x</script>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	htmlPath := filepath.Join(dir, "report.html")
	if err := WriteReportHTMLFallback(md, htmlPath); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "<!DOCTYPE html>") || !strings.Contains(s, `<meta charset="utf-8">`) {
		t.Fatal(s)
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Fatal("expected escaped script")
	}
	if strings.Contains(s, "<script>") {
		t.Fatal("unescaped script")
	}
}
