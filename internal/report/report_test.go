package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestRenderMarkdown_includesEvidenceByDefault(t *testing.T) {
	evID := "ev-1"
	findings := []model.Finding{
		{
			FindingID:       "f1",
			RuleID:          "r1",
			Severity:        model.SeverityHigh,
			LifecycleStatus: model.LifecycleDetected,
			Title:           "XSS",
			EvidenceRefs:    []string{evID},
		},
	}
	evidence := map[string]model.Evidence{
		evID: {
			EvidenceID: evID,
			Type:       model.EvidenceHTTPRequestResponse,
			Payload: map[string]any{
				"method":              "GET",
				"url":                 "https://x.test/a",
				"statusCode":          float64(200),
				"responseBodySnippet": "<script>",
			},
		},
	}
	out := RenderMarkdown("j", "https://x.test", "Fast", time.Time{}, time.Time{}, findings, evidence, true, "low", nil)
	s := string(out)
	if !containsAll(s, []string{"## Evidence", "GET", "https://x.test/a", "<script>"}) {
		t.Fatalf("report missing evidence: %s", s)
	}
	if strings.Contains(s, "## Evidence (confirmed)") {
		t.Fatal("old section title")
	}
	if !strings.Contains(s, "## Evidence summary") {
		t.Fatal("missing evidence summary")
	}
}

func TestRenderMarkdown_evidenceSummaryQuality(t *testing.T) {
	evID := "e1"
	findings := []model.Finding{{
		FindingID: "f1", RuleID: "r", Severity: model.SeverityInfo,
		LifecycleStatus: model.LifecycleDetected, EvidenceRefs: []string{evID},
	}}
	evidence := map[string]model.Evidence{
		evID: {Type: model.EvidenceHTTPRequestResponse, Payload: model.HTTPRequestResponsePayload{
			Method: "GET", URL: "http://u/",
		}},
	}
	out := string(RenderMarkdown("j", "", "", time.Time{}, time.Time{}, findings, evidence, false, "high", nil))
	if !strings.Contains(out, "partial") || !strings.Contains(out, "Evidence summary") {
		t.Fatal(out)
	}
}

func TestRenderMarkdown_httpTypedPayload(t *testing.T) {
	evID := "e2"
	findings := []model.Finding{
		{
			FindingID:       "f1",
			EvidenceRefs:    []string{evID},
			LifecycleStatus: model.LifecycleConfirmed,
			Title:           "t",
		},
	}
	evidence := map[string]model.Evidence{
		evID: {
			EvidenceID: evID,
			Type:       model.EvidenceHTTPRequestResponse,
			Payload: model.HTTPRequestResponsePayload{
				Method:              "POST",
				URL:                 "https://a/b",
				StatusCode:          500,
				ResponseBodySnippet: "err",
			},
		},
	}
	out := string(RenderMarkdown("", "", "", time.Time{}, time.Time{}, findings, evidence, true, "low", nil))
	if !containsAll(out, []string{"POST", "https://a/b", "500", "err"}) {
		t.Fatal(out)
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
