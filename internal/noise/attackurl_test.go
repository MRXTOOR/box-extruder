package noise_test

import (
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
)

func TestIsAttackPayloadURL_XSSPatterns(t *testing.T) {
	xss := []string{
		"https://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"https://example.com/?x=javascript:alert(1)",
		"https://example.com/page?q=<svg/onload=alert(1)>",
		"https://example.com/?q=onerror=alert(document.cookie)",
		"https://example.com/?q=document.cookie",
	}
	for _, u := range xss {
		if !noise.IsAttackPayloadURL(u) {
			t.Errorf("should be attack payload: %s", u)
		}
	}
}

func TestIsAttackPayloadURL_SQLiPatterns(t *testing.T) {
	sqli := []string{
		"https://example.com/?q=%27+OR+%271%27%3D%271",
		"https://example.com/?q=%27+AND+%271%27%3D%272",
		"https://example.com/api?q=%27+UNION+SELECT+null--",
		"https://example.com/?q=%27%3B+CREATE+TABLE+test+%28id+INT%29%3B--",
	}
	for _, u := range sqli {
		if !noise.IsAttackPayloadURL(u) {
			t.Errorf("should be attack payload: %s", u)
		}
	}
}

func TestIsAttackPayloadURL_NormalURLs(t *testing.T) {
	normal := []string{
		"https://sfera.release.dev.sfera-t1.ru/api/tenant/v1/user/routes",
		"https://example.com/api/v1/entities?page=1&size=20",
	}
	for _, u := range normal {
		if noise.IsAttackPayloadURL(u) {
			t.Errorf("should NOT be attack payload: %s", u)
		}
	}
}

func TestApply_excludesCrawlTelemetryFindings(t *testing.T) {
	in := []model.Finding{
		{RuleID: "katana:discovered-url", Category: "crawl-discovery", Severity: model.SeverityInfo},
		{RuleID: "10038", Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleDetected},
	}
	out := noise.Apply(config.DefaultScanAsCode(), in, nil)
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1 (crawl telemetry excluded)", len(out))
	}
	if out[0].RuleID != "10038" {
		t.Fatalf("unexpected rule %q", out[0].RuleID)
	}
}
