package webscan

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// parsedBuildYAML is a helper that calls BuildScanYAML and returns both the raw
// bytes and the unmarshalled doc so individual assertions can be concise.
func parsedBuildYAML(t *testing.T, opts CreateOptions) ([]byte, map[string]any) {
	t.Helper()
	b, err := BuildScanYAML(opts)
	if err != nil {
		t.Fatalf("BuildScanYAML: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	return b, doc
}

func zapStep(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	scan, _ := doc["scan"].(map[string]any)
	plan, _ := scan["plan"].([]any)
	for _, s := range plan {
		m, _ := s.(map[string]any)
		if m["stepType"] == "zapBaseline" {
			return m
		}
	}
	t.Fatal("no zapBaseline step in plan")
	return nil
}

func katanaStep(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	scan, _ := doc["scan"].(map[string]any)
	plan, _ := scan["plan"].([]any)
	for _, s := range plan {
		m, _ := s.(map[string]any)
		if m["stepType"] == "katana" {
			return m
		}
	}
	t.Fatal("no katana step in plan")
	return nil
}

// ── Plan structure ────────────────────────────────────────────────────────────

func TestBuildScanYAML_PipelineAndDiscovery(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{
		Target: "https://sfera.example/app/dashboard",
		JobID:  "test-job",
	})
	budgets, _ := doc["budgets"].(map[string]any)
	disc, _ := budgets["discovery"].(map[string]any)
	if disc["preserveQuery"] != true {
		t.Fatalf("preserveQuery: %v", disc["preserveQuery"])
	}
	scan, _ := doc["scan"].(map[string]any)
	plan, _ := scan["plan"].([]any)
	if len(plan) != 4 {
		t.Fatalf("plan steps: want 4 (katana,zap,wapiti,nuclei), got %d", len(plan))
	}
	s0, _ := plan[0].(map[string]any)
	if s0["stepType"] != "katana" || s0["katanaHeadless"] != true {
		t.Fatalf("katana step: %v", s0)
	}
	s1, _ := plan[1].(map[string]any)
	if s1["stepType"] != "zapBaseline" {
		t.Fatalf("step1: %v", s1["stepType"])
	}
	s2, _ := plan[2].(map[string]any)
	if s2["stepType"] != "wapiti" {
		t.Fatalf("step2: %v", s2["stepType"])
	}
	s3, _ := plan[3].(map[string]any)
	if s3["stepType"] != "nucleiTemplates" {
		t.Fatalf("step3: %v", s3["stepType"])
	}
}

// ── SPA defaults on the ZAP step ─────────────────────────────────────────────

func TestBuildScanYAML_ZAPStep_SPAContextExcludeStaticEnabled(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	zap := zapStep(t, doc)
	if zap["zapContextExcludeStatic"] != true {
		t.Fatalf("zapContextExcludeStatic must be true for UI scans, got %v", zap["zapContextExcludeStatic"])
	}
}

func TestBuildScanYAML_ZAPStep_AjaxTimingEnabled(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	zap := zapStep(t, doc)
	if zap["zapAjaxEventWait"] != 1000 {
		t.Fatalf("zapAjaxEventWait: want 1000, got %v", zap["zapAjaxEventWait"])
	}
	if zap["zapAjaxReloadWait"] != 1000 {
		t.Fatalf("zapAjaxReloadWait: want 1000, got %v", zap["zapAjaxReloadWait"])
	}
}

func TestBuildScanYAML_ZAPStep_AjaxSpiderEnabled(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	zap := zapStep(t, doc)
	if zap["zapSpiderAjax"] != true {
		t.Fatalf("zapSpiderAjax must be true, got %v", zap["zapSpiderAjax"])
	}
	if zap["zapSpiderTraditional"] != true {
		t.Fatalf("zapSpiderTraditional must be true, got %v", zap["zapSpiderTraditional"])
	}
	if zap["zapAutomationFramework"] != true {
		t.Fatalf("zapAutomationFramework must be true, got %v", zap["zapAutomationFramework"])
	}
}

func TestBuildScanYAML_ZAPStep_DefaultSpiderMinutes(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	zap := zapStep(t, doc)
	// Default is 15 minutes when not overridden.
	if zap["zapMaxSpiderMinutes"] != 15 {
		t.Fatalf("zapMaxSpiderMinutes: want 15, got %v", zap["zapMaxSpiderMinutes"])
	}
}

func TestBuildScanYAML_ZAPStep_CustomSpiderMinutes(t *testing.T) {
	min := 30
	_, doc := parsedBuildYAML(t, CreateOptions{
		Target:           "https://sfera.example.ru/",
		ZapSpiderMinutes: &min,
	})
	zap := zapStep(t, doc)
	if zap["zapMaxSpiderMinutes"] != 30 {
		t.Fatalf("zapMaxSpiderMinutes: want 30, got %v", zap["zapMaxSpiderMinutes"])
	}
}

// ── Scope.Deny for binary assets ─────────────────────────────────────────────

func TestBuildScanYAML_ScopeDeny_BinaryAssets(t *testing.T) {
	raw, _ := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	if !strings.Contains(string(raw), "deny:") {
		t.Fatal("scope.deny must be present in YAML output")
	}
	// All binary-asset extensions should appear in the deny pattern.
	for _, ext := range []string{"ttf", "woff", "png", "jpg", "ico", "svg", "pdf"} {
		if !strings.Contains(string(raw), ext) {
			t.Errorf("scope.deny missing extension %q", ext)
		}
	}
}

func TestBuildScanYAML_ScopeDeny_DoesNotExcludeJS(t *testing.T) {
	// Katana uses -jc to extract API endpoints from JS bundles; .js must NOT be denied.
	raw, _ := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	scope := string(raw)
	// Find the deny block and ensure .js isn't in it.
	denyStart := strings.Index(scope, "deny:")
	if denyStart < 0 {
		t.Fatal("no deny: block")
	}
	allowStart := strings.Index(scope, "allow:")
	denyBlock := ""
	if allowStart > denyStart {
		denyBlock = scope[denyStart:allowStart]
	} else {
		denyBlock = scope[denyStart : denyStart+300]
	}
	if strings.Contains(denyBlock, `\.js\b`) || strings.Contains(denyBlock, `\.js"`) {
		t.Fatalf("scope.deny must not exclude .js files (needed by Katana -jc): %s", denyBlock)
	}
}

// ── Katana step ───────────────────────────────────────────────────────────────

func TestBuildScanYAML_KatanaStep_HeadlessAndJC(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	kat := katanaStep(t, doc)
	if kat["katanaHeadless"] != true {
		t.Fatalf("katanaHeadless must be true")
	}
	extraArgs, _ := kat["katanaExtraArgs"].([]any)
	found := false
	for _, a := range extraArgs {
		if a.(string) == "-jc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("katanaExtraArgs must contain -jc: %v", extraArgs)
	}
}

func TestBuildScanYAML_KatanaStep_CustomDepth(t *testing.T) {
	depth := 4
	_, doc := parsedBuildYAML(t, CreateOptions{
		Target:       "https://sfera.example.ru/",
		KatanaDepth:  &depth,
	})
	kat := katanaStep(t, doc)
	if kat["katanaDepth"] != 4 {
		t.Fatalf("katanaDepth: want 4, got %v", kat["katanaDepth"])
	}
}

// ── Target / scope ────────────────────────────────────────────────────────────

func TestBuildScanYAML_NormalizesBaseURL(t *testing.T) {
	// A deep URL like /app/dashboard should still result in the site root as baseUrl.
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/app/dashboard"})
	targets, _ := doc["targets"].([]any)
	if len(targets) == 0 {
		t.Fatal("no targets")
	}
	t0, _ := targets[0].(map[string]any)
	if t0["baseUrl"] != "https://sfera.example.ru" {
		t.Fatalf("baseUrl: got %v", t0["baseUrl"])
	}
}

func TestBuildScanYAML_SeedIncludesRootWhenDeepURL(t *testing.T) {
	// Root must always be added to startPoints when a deep target URL is provided.
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/app/dashboard"})
	targets, _ := doc["targets"].([]any)
	t0, _ := targets[0].(map[string]any)
	starts, _ := t0["startPoints"].([]any)
	var urls []string
	for _, s := range starts {
		urls = append(urls, s.(string))
	}
	hasRoot := false
	for _, u := range urls {
		if u == "https://sfera.example.ru" {
			hasRoot = true
		}
	}
	if !hasRoot {
		t.Fatalf("startPoints must include root URL: %v", urls)
	}
}

func TestBuildScanYAML_ScopeAllowPattern(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.release.dev.sfera-t1.ru/"})
	scope, _ := doc["scope"].(map[string]any)
	allow, _ := scope["allow"].([]any)
	if len(allow) != 1 {
		t.Fatalf("scope.allow: want 1 pattern, got %v", allow)
	}
	pat := allow[0].(string)
	// Must anchor to the correct host.
	if !strings.Contains(pat, `sfera\.release\.dev\.sfera-t1\.ru`) {
		t.Fatalf("scope.allow pattern doesn't match target host: %s", pat)
	}
}

func TestBuildScanYAML_ErrorOnMissingTarget(t *testing.T) {
	if _, err := BuildScanYAML(CreateOptions{Target: ""}); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestBuildScanYAML_ErrorOnInvalidTarget(t *testing.T) {
	if _, err := BuildScanYAML(CreateOptions{Target: "not-a-url"}); err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// ── Budgets ───────────────────────────────────────────────────────────────────

func TestBuildScanYAML_Budgets_Defaults(t *testing.T) {
	_, doc := parsedBuildYAML(t, CreateOptions{Target: "https://sfera.example.ru/"})
	budgets, _ := doc["budgets"].(map[string]any)
	disc, _ := budgets["discovery"].(map[string]any)
	if disc["maxDepth"] != 6 {
		t.Fatalf("maxDepth: want 6, got %v", disc["maxDepth"])
	}
	if disc["maxUrls"] != 3000 {
		t.Fatalf("maxUrls: want 3000, got %v", disc["maxUrls"])
	}
	if disc["preserveQuery"] != true {
		t.Fatalf("preserveQuery: want true")
	}
}

func TestBuildScanYAML_Budgets_CustomKatanaDepth(t *testing.T) {
	depth := 3
	_, doc := parsedBuildYAML(t, CreateOptions{
		Target:      "https://sfera.example.ru/",
		KatanaDepth: &depth,
	})
	budgets, _ := doc["budgets"].(map[string]any)
	disc, _ := budgets["discovery"].(map[string]any)
	if disc["maxDepth"] != 3 {
		t.Fatalf("maxDepth: want 3, got %v", disc["maxDepth"])
	}
}

func TestBuildScanYAML_Budgets_CustomMaxURLs(t *testing.T) {
	maxU := 500
	_, doc := parsedBuildYAML(t, CreateOptions{
		Target:       "https://sfera.example.ru/",
		KatanaMaxURLs: &maxU,
	})
	budgets, _ := doc["budgets"].(map[string]any)
	disc, _ := budgets["discovery"].(map[string]any)
	if disc["maxUrls"] != 500 {
		t.Fatalf("maxUrls: want 500, got %v", disc["maxUrls"])
	}
}
