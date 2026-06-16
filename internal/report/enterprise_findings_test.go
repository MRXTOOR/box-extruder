package report

import (
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/model"
)

func TestEnterpriseReportFindings_filtersConfirmedNonInfo(t *testing.T) {
	in := []model.Finding{
		{Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleConfirmed},
		{Severity: model.SeverityInfo, LifecycleStatus: model.LifecycleConfirmed},
		{Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleDetected},
		{Severity: model.SeverityLow, LifecycleStatus: model.LifecycleFalsePositiveSuppressed},
	}
	out := enterpriseReportFindings(in)
	if len(out) != 1 || out[0].Severity != model.SeverityHigh {
		t.Fatalf("got %d findings, want 1 confirmed non-info", len(out))
	}
}

func TestFindingIdentifier_stripsToolAndUsesCWE(t *testing.T) {
	f := model.Finding{RuleID: "10038", Title: "CSP Header Not Set"}
	if got := findingIdentifier(f); got != "CWE-693" {
		t.Fatalf("identifier = %q, want CWE-693", got)
	}
	w := model.Finding{RuleID: "wapiti:content-security-policy-configuration", Title: "Wapiti: Content Security Policy Configuration"}
	if got := findingIdentifier(w); got != "content-security-policy-configuration" {
		t.Fatalf("identifier = %q", got)
	}
}

func TestFindingDescription_includesEndpointAndRussian(t *testing.T) {
	f := model.Finding{
		RuleID:      "wapiti:content-security-policy-configuration",
		Title:       "Wapiti: Content Security Policy Configuration",
		Description: `CSP "default-src" value is not safe`,
		LocationKey: "GET https://app.example.com/dashboard",
		Severity:    model.SeverityMedium,
	}
	desc := findingDescription(f)
	for _, want := range []string{"Небезопасная конфигурация Content Security Policy", "https://app.example.com/dashboard"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description %q missing %q", desc, want)
		}
	}
	if strings.Contains(desc, "Эндпоинт") {
		t.Fatalf("description must not contain Эндпоинт label: %q", desc)
	}
}

func TestAnalysisType_alwaysDAST(t *testing.T) {
	f := model.Finding{Category: "CONTENT SECURITY POLICY CONFIGURATION", RuleID: "wapiti:foo"}
	if got := analysisType(f); got != "DAST" {
		t.Fatalf("analysisType = %q", got)
	}
}

func TestAssessSecurityLevel_criticalMeansLow(t *testing.T) {
	findings := []model.Finding{{Severity: model.SeverityCritical, LifecycleStatus: model.LifecycleConfirmed}}
	assess := assessSecurityLevel(findings)
	if assess.Level != "низкий" {
		t.Fatalf("level = %q", assess.Level)
	}
}

func TestFormatConclusions_structure(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityCritical, LifecycleStatus: model.LifecycleConfirmed},
		{Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleConfirmed},
		{Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed},
		{Severity: model.SeverityLow, LifecycleStatus: model.LifecycleConfirmed},
	}
	text := formatConclusions(findings)
	if !strings.Contains(text, "выявлено 4 уязвимости") {
		t.Fatalf("unexpected total phrase: %q", text)
	}
	if !strings.Contains(text, "низкий уровень защищённости") {
		t.Fatalf("missing security level: %q", text)
	}
}

func TestRenderEnterpriseMarkdown_noExcludedScopeText(t *testing.T) {
	md := string(RenderEnterpriseMarkdown(Data{
		BaseURL: "https://example.com",
		Findings: []model.Finding{{
			RuleID: "10038", Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: "GET https://example.com/",
		}},
	}))
	if strings.Contains(md, "Исключённые из тестирования") {
		t.Fatal("SAST/SCA exclusion text must be removed")
	}
	if !strings.Contains(md, "DAST") || !strings.Contains(md, "Выводы") {
		t.Fatal("expected DAST sections in markdown")
	}
}
