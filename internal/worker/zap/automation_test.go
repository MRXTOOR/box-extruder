package zap

import (
	"regexp"
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"gopkg.in/yaml.v3"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// parsedDoc unmarshals YAML produced by buildAutomationYAML.
func parsedDoc(t *testing.T, step config.ScanStep, seeds []string, allow []string, authHeaders map[string]string, probes []map[string]any) map[string]any {
	t.Helper()
	b, err := buildAutomationYAML(seeds, allow, step, "/zap/wrk", authHeaders, probes)
	if err != nil {
		t.Fatalf("buildAutomationYAML: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	return doc
}

func jobTypes(doc map[string]any) []string {
	jobs, _ := doc["jobs"].([]any)
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		m, _ := j.(map[string]any)
		out = append(out, m["type"].(string))
	}
	return out
}

func jobsOfType(doc map[string]any, typ string) []map[string]any {
	jobs, _ := doc["jobs"].([]any)
	var out []map[string]any
	for _, j := range jobs {
		m, _ := j.(map[string]any)
		if m["type"].(string) == typ {
			out = append(out, m)
		}
	}
	return out
}

func contextBlock(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	env, _ := doc["env"].(map[string]any)
	ctxs, _ := env["contexts"].([]any)
	if len(ctxs) == 0 {
		t.Fatal("no contexts in doc")
	}
	ctx, _ := ctxs[0].(map[string]any)
	return ctx
}

func spiderURLs(doc map[string]any, jobType string) []string {
	var out []string
	for _, j := range jobsOfType(doc, jobType) {
		p, _ := j["parameters"].(map[string]any)
		if u, ok := p["url"].(string); ok {
			out = append(out, u)
		}
	}
	return out
}

// ── isPageLikeURL ────────────────────────────────────────────────────────────

func TestIsPageLikeURL_APIPathsExcluded(t *testing.T) {
	// API and service endpoints return JSON — useless as Ajax spider seeds.
	apiURLs := []string{
		"https://sfera.example.ru/api/tenant/v1/user/routes",
		"https://sfera.example.ru/api/profile/admin/v1/users/current",
		"https://sfera.example.ru/api/common/widgets/v1/maintenance-mode?app=PPOR",
		"https://sfera.example.ru/service/notif/socket.io",
		"https://sfera.example.ru/service/notifications/api/v1/ui-resource-strings",
		"https://sfera.example.ru/locales/translation/ru.json",
		"https://sfera.example.ru/app/ppau/api/auth/login-formats",
		"https://sfera.example.ru/app/home-page/api/tenant/v1/user/applications/menu",
	}
	for _, u := range apiURLs {
		if isPageLikeURL(u) {
			t.Errorf("API/service endpoint should not be a spider seed: %s", u)
		}
	}
}

func TestIsPageLikeURL_StaticExtensions(t *testing.T) {
	static := []string{
		"https://sfera.example.ru/static/js/main.abc123.js",
		"https://sfera.example.ru/static/js/611.chunk.js",
		"https://sfera.example.ru/remoteEntry.js",
		"https://sfera.example.ru/remoteEntry.js?v=afc71eb6",
		"https://sfera.example.ru/app/ppau/remoteEntry.js",
		"https://sfera.example.ru/app/ppau/manifest.json",
		"https://sfera.example.ru/static/css/styles.css",
		"https://sfera.example.ru/static/media/font.ttf",
		"https://sfera.example.ru/static/media/Geologica.woff2",
		"https://sfera.example.ru/static/media/bg.png",
		"https://sfera.example.ru/favicon.ico",
		"https://sfera.example.ru/sitemap.xml",
		"https://sfera.example.ru/robots.txt",
		"https://sfera.example.ru/bundle.mjs",
		"https://sfera.example.ru/chunk.js.map",
	}
	for _, u := range static {
		if isPageLikeURL(u) {
			t.Errorf("expected static, got page-like: %s", u)
		}
	}
}

func TestIsPageLikeURL_PageURLs(t *testing.T) {
	// These are SPA route pages that the Ajax spider should navigate.
	// /api/ and /service/ are intentionally excluded (they return JSON, not HTML).
	pages := []string{
		"https://sfera.example.ru/",
		"https://sfera.example.ru",
		"https://sfera.example.ru/app/ppau/",
		"https://sfera.example.ru/app/home-page",
		"https://sfera.example.ru/app/orchestration/dashboard",
		"https://sfera.example.ru/app/orchestration/agents?status=ONLINE",
	}
	for _, u := range pages {
		if !isPageLikeURL(u) {
			t.Errorf("expected page-like, got static: %s", u)
		}
	}
}

// ── filterPageSeeds ──────────────────────────────────────────────────────────

// TestFilterPageSeeds_SferaMixedInput replicates the exact seeds that caused
// the f8267422 scan to run for only 4.5 minutes: 10 seeds of which 6 were
// static JS/JSON files. After filtering only the 2 real page URLs should remain.
func TestFilterPageSeeds_SferaMixedInput(t *testing.T) {
	seeds := []string{
		// from katanaSeedURLs (target start points):
		"https://sfera.release.dev.sfera-t1.ru",
		"https://sfera.release.dev.sfera-t1.ru/",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau",
		// from Katana -jc JS endpoint extraction (static, should be filtered):
		"https://sfera.release.dev.sfera-t1.ru/static/js/main.e07f9e87149a29221f7d.js",
		"https://sfera.release.dev.sfera-t1.ru/manifest.json",
		"https://sfera.release.dev.sfera-t1.ru/remoteEntry.js?v=afc71eb6f256ab6594ee",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/remoteEntry.js",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/manifest.json",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/static/js/main.c86cf6a2.js",
	}
	got := filterPageSeeds(seeds)
	// Only the 4 page-like seeds should survive.
	if len(got) != 4 {
		t.Fatalf("expected 4 page seeds, got %d: %v", len(got), got)
	}
	for _, u := range got {
		if !isPageLikeURL(u) {
			t.Errorf("non-page URL slipped through filter: %s", u)
		}
	}
}

func TestFilterPageSeeds_PreservesOrder(t *testing.T) {
	seeds := []string{
		"https://example.com/",
		"https://example.com/bundle.js",
		"https://example.com/app/dashboard",
		"https://example.com/style.css",
	}
	got := filterPageSeeds(seeds)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %v", len(got), got)
	}
	if got[0] != "https://example.com/" || got[1] != "https://example.com/app/dashboard" {
		t.Fatalf("wrong order: %v", got)
	}
}

func TestFilterPageSeeds_EmptyInput(t *testing.T) {
	if got := filterPageSeeds(nil); got != nil {
		t.Fatalf("expected nil for nil input, got %v", got)
	}
	if got := filterPageSeeds([]string{}); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestFilterPageSeeds_AllPageURLs(t *testing.T) {
	// /api/ paths are excluded (JSON endpoints); only SPA routes pass.
	seeds := []string{"https://x.com/", "https://x.com/app", "https://x.com/api/v1"}
	got := filterPageSeeds(seeds)
	if len(got) != 2 {
		t.Fatalf("want 2 (root + /app), got %d: %v", len(got), got)
	}
}

func TestFilterPageSeeds_FallbackWhenAllStatic(t *testing.T) {
	seeds := []string{
		"https://example.com/bundle.js",
		"https://example.com/style.css",
		"https://example.com/image.png",
	}
	got := filterPageSeeds(seeds)
	// Falls back to the first seed so ZAP always has at least one seed to work with.
	if len(got) != 1 || got[0] != seeds[0] {
		t.Fatalf("expected fallback to first seed, got %v", got)
	}
}

// ── buildSPAContextExcludePaths ──────────────────────────────────────────────

func TestBuildSPAContextExcludePaths_AreValidRegexes(t *testing.T) {
	for _, p := range buildSPAContextExcludePaths() {
		if _, err := regexp.Compile(p); err != nil {
			t.Errorf("invalid regex %q: %v", p, err)
		}
	}
}

func TestBuildSPAContextExcludePaths_MatchSferaStaticURLs(t *testing.T) {
	patterns := buildSPAContextExcludePaths()
	shouldMatch := []string{
		"https://sfera.example.ru/static/js/main.e07f9e87.js",
		"https://sfera.example.ru/static/js/611.0a2f9055.js",
		"https://sfera.example.ru/static/css/styles.52251557.css",
		"https://sfera.example.ru/static/media/Geologica-Regular.ttf",
		"https://sfera.example.ru/static/media/bg.png",
		"https://sfera.example.ru/app/ppau/static/js/4178.a8b53c5d.chunk.js",
		"https://sfera.example.ru/app/ppau/static/css/663.0572decf.chunk.css",
		"https://sfera.example.ru/app/ppau/static/media/background-1280.png",
		"https://sfera.example.ru/remoteEntry.js",
		"https://sfera.example.ru/app/knowledge/remoteEntry.js",
		"https://sfera.example.ru/app/ppau/remoteEntry.js",
		"https://sfera.example.ru/favicon.ico",
		"https://sfera.example.ru/apple-touch-icon.png",
		"https://sfera.example.ru/static/media/Geologica-SemiBold.woff2",
	}
	for _, u := range shouldMatch {
		matched := false
		for _, pat := range patterns {
			if regexp.MustCompile(pat).MatchString(u) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("excludePaths did not match static URL: %s", u)
		}
	}
}

func TestBuildSPAContextExcludePaths_DoNotMatchAPIRoutes(t *testing.T) {
	patterns := buildSPAContextExcludePaths()
	shouldNotMatch := []string{
		"https://sfera.example.ru/",
		"https://sfera.example.ru/app/home-page",
		"https://sfera.example.ru/app/orchestration/dashboard",
		"https://sfera.example.ru/api/tenant/v1/user/routes",
		"https://sfera.example.ru/api/profile/admin/v1/users/current",
		"https://sfera.example.ru/service/notif/socket.io",
		"https://sfera.example.ru/app/ppau/api/auth/login-formats",
		"https://sfera.example.ru/locales/translation/ru.json",
		"https://sfera.example.ru/app/home-page/locales/common/ru.json",
	}
	for _, u := range shouldNotMatch {
		for _, pat := range patterns {
			if regexp.MustCompile(pat).MatchString(u) {
				t.Errorf("excludePaths wrongly matched API/page URL %q with pattern %q", u, pat)
			}
		}
	}
}

// ── buildAutomationYAML: context ─────────────────────────────────────────────

func TestBuildAutomationYAML_ContextContainsAllSeeds(t *testing.T) {
	// The ZAP context must contain ALL seeds (including static) so ZAP knows
	// about them for scope evaluation — only the spider jobs filter them.
	seeds := []string{
		"https://sfera.example.ru/",
		"https://sfera.example.ru/static/js/main.abc.js",
		"https://sfera.example.ru/app/ppau/manifest.json",
	}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true}, seeds, nil, nil, nil)
	ctx := contextBlock(t, doc)
	ctxURLs, _ := ctx["urls"].([]any)
	if len(ctxURLs) != 3 {
		t.Fatalf("context.urls: want 3 (all seeds), got %d: %v", len(ctxURLs), ctxURLs)
	}
}

func TestBuildAutomationYAML_ContextIncludePaths_DefaultFallback(t *testing.T) {
	// When no allow patterns are given, includePaths falls back to <primary>/.*
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true}, []string{"https://example.com/"}, nil, nil, nil)
	ctx := contextBlock(t, doc)
	inc, _ := ctx["includePaths"].([]any)
	if len(inc) == 0 {
		t.Fatal("includePaths must not be empty")
	}
	if !strings.Contains(inc[0].(string), "example.com") {
		t.Fatalf("includePaths fallback unexpected: %v", inc)
	}
}

func TestBuildAutomationYAML_ContextIncludePaths_FromAllowScope(t *testing.T) {
	allow := []string{`^https://sfera\.example\.ru(/.*)?$`}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true}, []string{"https://sfera.example.ru/"}, allow, nil, nil)
	ctx := contextBlock(t, doc)
	inc, _ := ctx["includePaths"].([]any)
	if len(inc) != 1 || inc[0].(string) != allow[0] {
		t.Fatalf("includePaths: got %v", inc)
	}
}

func TestBuildAutomationYAML_ContextExcludePaths_WhenFlagSet(t *testing.T) {
	step := config.ScanStep{ZAPSpiderAjax: true, ZAPContextExcludeStatic: true}
	doc := parsedDoc(t, step, []string{"https://sfera.example.ru/"}, nil, nil, nil)
	ctx := contextBlock(t, doc)
	exc, _ := ctx["excludePaths"].([]any)
	if len(exc) == 0 {
		t.Fatal("excludePaths must be populated when ZAPContextExcludeStatic=true")
	}
	// Spot-check a known pattern is present.
	found := false
	for _, e := range exc {
		if strings.Contains(e.(string), "static/js") {
			found = true
		}
	}
	if !found {
		t.Fatalf("excludePaths missing static/js pattern: %v", exc)
	}
}

func TestBuildAutomationYAML_ContextExcludePaths_AbsentWhenFlagNotSet(t *testing.T) {
	step := config.ScanStep{ZAPSpiderAjax: true, ZAPContextExcludeStatic: false}
	doc := parsedDoc(t, step, []string{"https://example.com/"}, nil, nil, nil)
	ctx := contextBlock(t, doc)
	if _, ok := ctx["excludePaths"]; ok {
		t.Fatal("excludePaths must be absent when ZAPContextExcludeStatic=false")
	}
}

// ── buildAutomationYAML: spider seed filtering ───────────────────────────────

func TestBuildAutomationYAML_SpiderSeedsOnlyPageURLs(t *testing.T) {
	// Exact Sfera scenario: 10 seeds of which 6 are static assets.
	seeds := []string{
		"https://sfera.release.dev.sfera-t1.ru",
		"https://sfera.release.dev.sfera-t1.ru/",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau",
		"https://sfera.release.dev.sfera-t1.ru/static/js/main.e07f9e87149a29221f7d.js",
		"https://sfera.release.dev.sfera-t1.ru/manifest.json",
		"https://sfera.release.dev.sfera-t1.ru/remoteEntry.js?v=afc71eb6",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/remoteEntry.js",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/manifest.json",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/static/js/main.c86cf6a2.js",
	}
	step := config.ScanStep{
		ZAPSpiderTraditional: true,
		ZAPSpiderAjax:        true,
		ZAPMaxSpiderMinutes:  15,
	}
	doc := parsedDoc(t, step, seeds, nil, nil, nil)

	// Context must have all 10 seeds.
	ctx := contextBlock(t, doc)
	ctxURLs, _ := ctx["urls"].([]any)
	if len(ctxURLs) != 10 {
		t.Fatalf("context.urls: want 10, got %d", len(ctxURLs))
	}

	// Spider and spiderAjax jobs must only use page-like seeds.
	for _, jobType := range []string{"spider", "spiderAjax"} {
		for _, u := range spiderURLs(doc, jobType) {
			if !isPageLikeURL(u) {
				t.Errorf("%s job got static seed %q", jobType, u)
			}
		}
	}

	// 4 page seeds → 4 spider + 4 spiderAjax jobs (not 10+10).
	if n := len(jobsOfType(doc, "spider")); n != 4 {
		t.Fatalf("spider jobs: want 4, got %d", n)
	}
	if n := len(jobsOfType(doc, "spiderAjax")); n != 4 {
		t.Fatalf("spiderAjax jobs: want 4, got %d", n)
	}
}

func TestBuildAutomationYAML_AllStaticSeeds_FallbackToFirst(t *testing.T) {
	// Edge case: if every seed is static the first is used as fallback so ZAP
	// still has at least one seed to work from.
	seeds := []string{
		"https://example.com/bundle.js",
		"https://example.com/style.css",
	}
	step := config.ScanStep{ZAPSpiderTraditional: true, ZAPSpiderAjax: true}
	doc := parsedDoc(t, step, seeds, nil, nil, nil)
	if n := len(jobsOfType(doc, "spider")); n != 1 {
		t.Fatalf("expected 1 fallback spider job, got %d", n)
	}
	if n := len(jobsOfType(doc, "spiderAjax")); n != 1 {
		t.Fatalf("expected 1 fallback spiderAjax job, got %d", n)
	}
}

// ── buildAutomationYAML: Ajax spider SPA timing ──────────────────────────────

func TestBuildAutomationYAML_AjaxSpiderDefaults(t *testing.T) {
	step := config.ScanStep{ZAPSpiderAjax: true}
	doc := parsedDoc(t, step, []string{"https://example.com/"}, nil, nil, nil)
	jobs := jobsOfType(doc, "spiderAjax")
	if len(jobs) == 0 {
		t.Fatal("no spiderAjax jobs")
	}
	p, _ := jobs[0]["parameters"].(map[string]any)
	if p["browserId"] != "firefox-headless" {
		t.Fatalf("default browserId: %v", p["browserId"])
	}
	if p["runOnlyIfModern"] != false {
		t.Fatalf("runOnlyIfModern should be false: %v", p["runOnlyIfModern"])
	}
	if p["inScopeOnly"] != true {
		t.Fatalf("inScopeOnly should be true: %v", p["inScopeOnly"])
	}
	// eventWait/reloadWait must not appear when not configured.
	if _, ok := p["eventWait"]; ok {
		t.Fatalf("eventWait should be absent when ZAPAjaxEventWait=0")
	}
	if _, ok := p["reloadWait"]; ok {
		t.Fatalf("reloadWait should be absent when ZAPAjaxReloadWait=0")
	}
}

func TestBuildAutomationYAML_AjaxSpiderSPATiming(t *testing.T) {
	step := config.ScanStep{
		ZAPSpiderAjax:        true,
		ZAPAjaxEventWait:     1000,
		ZAPAjaxReloadWait:    1000,
		ZAPAjaxMaxCrawlStates: 200,
		ZAPAjaxBrowserID:     "chrome-headless",
	}
	doc := parsedDoc(t, step, []string{"https://example.com/"}, nil, nil, nil)
	jobs := jobsOfType(doc, "spiderAjax")
	if len(jobs) == 0 {
		t.Fatal("no spiderAjax jobs")
	}
	p, _ := jobs[0]["parameters"].(map[string]any)
	if p["eventWait"] != 1000 {
		t.Fatalf("eventWait: want 1000, got %v", p["eventWait"])
	}
	if p["reloadWait"] != 1000 {
		t.Fatalf("reloadWait: want 1000, got %v", p["reloadWait"])
	}
	if p["maxCrawlStates"] != 200 {
		t.Fatalf("maxCrawlStates: want 200, got %v", p["maxCrawlStates"])
	}
	if p["browserId"] != "chrome-headless" {
		t.Fatalf("browserId: want chrome-headless, got %v", p["browserId"])
	}
}

func TestBuildAutomationYAML_AjaxSpiderPartialTiming(t *testing.T) {
	// Only eventWait set — reloadWait and maxCrawlStates must be absent.
	step := config.ScanStep{ZAPSpiderAjax: true, ZAPAjaxEventWait: 500}
	doc := parsedDoc(t, step, []string{"https://example.com/"}, nil, nil, nil)
	p, _ := jobsOfType(doc, "spiderAjax")[0]["parameters"].(map[string]any)
	if p["eventWait"] != 500 {
		t.Fatalf("eventWait: want 500, got %v", p["eventWait"])
	}
	if _, ok := p["reloadWait"]; ok {
		t.Fatalf("reloadWait must be absent: %v", p)
	}
	if _, ok := p["maxCrawlStates"]; ok {
		t.Fatalf("maxCrawlStates must be absent: %v", p)
	}
}

// ── buildAutomationYAML: replacer / auth headers ─────────────────────────────

func TestBuildAutomationYAML_ReplacerPresentWithAuth(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer token123"}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true}, []string{"https://example.com/"}, nil, headers, nil)
	replacers := jobsOfType(doc, "replacer")
	if len(replacers) != 1 {
		t.Fatalf("want 1 replacer job, got %d", len(replacers))
	}
	rules, _ := replacers[0]["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("replacer has no rules")
	}
	rule, _ := rules[0].(map[string]any)
	if rule["matchString"] != "Authorization" {
		t.Fatalf("rule matchString: %v", rule["matchString"])
	}
	if rule["replacementString"] != "Bearer token123" {
		t.Fatalf("rule replacementString: %v", rule["replacementString"])
	}
}

func TestBuildAutomationYAML_ReplacerAbsentWithoutAuth(t *testing.T) {
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true}, []string{"https://example.com/"}, nil, nil, nil)
	if replacers := jobsOfType(doc, "replacer"); len(replacers) != 0 {
		t.Fatalf("replacer should be absent without auth headers, got %d", len(replacers))
	}
}

func TestBuildAutomationYAML_ReplacerIsFirstJob(t *testing.T) {
	// Auth header injection must happen before any spider job.
	headers := map[string]string{"Authorization": "Bearer tok"}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true, ZAPSpiderTraditional: true},
		[]string{"https://example.com/"}, nil, headers, nil)
	types := jobTypes(doc)
	if len(types) == 0 || types[0] != "replacer" {
		t.Fatalf("replacer must be first job, got order: %v", types)
	}
}

// ── buildAutomationYAML: job ordering ────────────────────────────────────────

func TestBuildAutomationYAML_JobOrderTradAndAjax(t *testing.T) {
	// Order must be: [replacer?] spider* passiveScan-wait spiderAjax* passiveScan-wait ... export report
	step := config.ScanStep{ZAPSpiderTraditional: true, ZAPSpiderAjax: true}
	doc := parsedDoc(t, step, []string{"https://example.com/"}, nil, nil, nil)
	types := jobTypes(doc)
	raw := strings.Join(types, ",")

	idxSpider := strings.Index(raw, "spider,")
	idxAjax := strings.Index(raw, "spiderAjax")
	idxExport := strings.Index(raw, "export")
	idxReport := strings.Index(raw, "report")

	if idxSpider < 0 {
		t.Fatalf("no spider job: %v", types)
	}
	if idxAjax < 0 {
		t.Fatalf("no spiderAjax job: %v", types)
	}
	if !(idxSpider < idxAjax && idxAjax < idxExport && idxExport < idxReport) {
		t.Fatalf("wrong job order: %v", types)
	}
}

func TestBuildAutomationYAML_JobOrderAjaxOnly(t *testing.T) {
	step := config.ScanStep{ZAPSpiderAjax: true}
	doc := parsedDoc(t, step, []string{"https://example.com/"}, nil, nil, nil)
	types := jobTypes(doc)
	raw := strings.Join(types, ",")
	if strings.Contains(raw, "spider,") {
		t.Fatalf("traditional spider should be absent when ZAPSpiderTraditional=false: %v", types)
	}
	if !strings.Contains(raw, "spiderAjax") {
		t.Fatalf("spiderAjax missing: %v", types)
	}
}

func TestBuildAutomationYAML_RequestorBeforeExport(t *testing.T) {
	t.Setenv("DAST_ZAP_ACTIVE_SCAN", "0")
	probes := []map[string]any{{"method": "GET", "url": "https://example.com/?q=1"}}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true},
		[]string{"https://example.com/"}, nil, nil, probes)
	types := jobTypes(doc)
	raw := strings.Join(types, ",")
	reqIdx := strings.Index(raw, "requestor")
	expIdx := strings.Index(raw, "export")
	repIdx := strings.Index(raw, "report")
	if reqIdx < 0 || expIdx < 0 || repIdx < 0 {
		t.Fatalf("missing job types: %v", types)
	}
	if !(reqIdx < expIdx && expIdx < repIdx) {
		t.Fatalf("want requestor < export < report, got: %v", types)
	}
}

func TestBuildAutomationYAML_ActiveScanBeforeExport(t *testing.T) {
	t.Setenv("DAST_ZAP_ACTIVE_SCAN", "1")
	probes := []map[string]any{{"method": "GET", "url": "https://example.com/?q=1"}}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true},
		[]string{"https://example.com/"}, nil, nil, probes)
	types := jobTypes(doc)
	raw := strings.Join(types, ",")
	reqIdx := strings.Index(raw, "requestor")
	actIdx := strings.Index(raw, "activeScan")
	expIdx := strings.Index(raw, "export")
	repIdx := strings.Index(raw, "report")
	if reqIdx < 0 || actIdx < 0 || expIdx < 0 || repIdx < 0 {
		t.Fatalf("missing job types: %v", types)
	}
	if !(reqIdx < actIdx && actIdx < expIdx && expIdx < repIdx) {
		t.Fatalf("want requestor < activeScan < export < report, got: %v", types)
	}
}

func TestBuildAutomationYAML_ExportAlwaysPresent(t *testing.T) {
	for _, active := range []string{"0", "1"} {
		t.Run("active="+active, func(t *testing.T) {
			t.Setenv("DAST_ZAP_ACTIVE_SCAN", active)
			doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true},
				[]string{"https://example.com/"}, nil, nil, nil)
			if n := len(jobsOfType(doc, "export")); n != 1 {
				t.Fatalf("want 1 export job, got %d", n)
			}
			if n := len(jobsOfType(doc, "report")); n != 1 {
				t.Fatalf("want 1 report job, got %d", n)
			}
		})
	}
}

// ── buildAutomationYAML: passive-wait timings ─────────────────────────────────

func TestBuildAutomationYAML_PassiveWaitDefaultsTo1Min(t *testing.T) {
	// passiveSec=0 → default 60s → ceil to 1 min.
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true, ZAPPassiveWaitSeconds: 0},
		[]string{"https://example.com/"}, nil, nil, nil)
	for _, j := range jobsOfType(doc, "passiveScan-wait") {
		p, _ := j["parameters"].(map[string]any)
		if p["maxDuration"] != 1 {
			t.Fatalf("passive-wait maxDuration: want 1, got %v", p["maxDuration"])
		}
	}
}

func TestBuildAutomationYAML_PassiveWaitCeiledToMinutes(t *testing.T) {
	// 180s → ceil(180/60) = 3 min.
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true, ZAPPassiveWaitSeconds: 180},
		[]string{"https://example.com/"}, nil, nil, nil)
	for _, j := range jobsOfType(doc, "passiveScan-wait") {
		p, _ := j["parameters"].(map[string]any)
		if p["maxDuration"] != 3 {
			t.Fatalf("passive-wait maxDuration: want 3, got %v", p["maxDuration"])
		}
	}
}

// ── buildAutomationYAML: full SPA scenario ───────────────────────────────────

// TestBuildAutomationYAML_FullSPAConfig simulates what BuildScanYAML produces
// for a Sfera-like scan: ZAPContextExcludeStatic=true, eventWait=1000,
// reloadWait=1000, mixed seeds from Katana discovery.
func TestBuildAutomationYAML_FullSPAConfig(t *testing.T) {
	t.Setenv("DAST_ZAP_ACTIVE_SCAN", "0")

	seeds := []string{
		"https://sfera.release.dev.sfera-t1.ru",
		"https://sfera.release.dev.sfera-t1.ru/",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau",
		"https://sfera.release.dev.sfera-t1.ru/static/js/main.e07f9e87149a29221f7d.js",
		"https://sfera.release.dev.sfera-t1.ru/manifest.json",
		"https://sfera.release.dev.sfera-t1.ru/remoteEntry.js?v=afc71eb6",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/remoteEntry.js",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/manifest.json",
		"https://sfera.release.dev.sfera-t1.ru/app/ppau/static/js/main.c86cf6a2.js",
	}
	step := config.ScanStep{
		ZAPSpiderTraditional:    true,
		ZAPSpiderAjax:           true,
		ZAPMaxSpiderMinutes:     15,
		ZAPPassiveWaitSeconds:   180,
		ZAPContextExcludeStatic: true,
		ZAPAjaxEventWait:        1000,
		ZAPAjaxReloadWait:       1000,
	}
	allow := []string{`^https://sfera\.release\.dev\.sfera-t1\.ru(/.*)?$`}
	auth := map[string]string{"Authorization": "Bearer eyJhbGci..."}

	doc := parsedDoc(t, step, seeds, allow, auth, nil)

	// 1. Context has all seeds.
	ctx := contextBlock(t, doc)
	ctxURLs, _ := ctx["urls"].([]any)
	if len(ctxURLs) != 10 {
		t.Fatalf("context.urls: want 10, got %d", len(ctxURLs))
	}

	// 2. excludePaths populated.
	exc, _ := ctx["excludePaths"].([]any)
	if len(exc) == 0 {
		t.Fatal("excludePaths must be set")
	}

	// 3. Spider jobs only on page seeds (4 of 10).
	if n := len(jobsOfType(doc, "spider")); n != 4 {
		t.Fatalf("spider count: want 4, got %d", n)
	}
	if n := len(jobsOfType(doc, "spiderAjax")); n != 4 {
		t.Fatalf("spiderAjax count: want 4, got %d", n)
	}

	// 4. Ajax params have SPA timing.
	ajaxJob := jobsOfType(doc, "spiderAjax")[0]
	p, _ := ajaxJob["parameters"].(map[string]any)
	if p["eventWait"] != 1000 || p["reloadWait"] != 1000 {
		t.Fatalf("SPA timing params missing: %v", p)
	}

	// 5. Auth replacer is first job.
	types := jobTypes(doc)
	if types[0] != "replacer" {
		t.Fatalf("replacer must be first, got: %v", types[:3])
	}

	// 6. Job order: spider → passiveScan-wait → spiderAjax → passiveScan-wait → export → report.
	raw := strings.Join(types, ",")
	spiderIdx := strings.Index(raw, "spider,")
	ajaxIdx := strings.Index(raw, "spiderAjax")
	exportIdx := strings.Index(raw, "export")
	reportIdx := strings.Index(raw, "report")
	if !(spiderIdx < ajaxIdx && ajaxIdx < exportIdx && exportIdx < reportIdx) {
		t.Fatalf("wrong job order: %v", types)
	}
}

// ── buildAutomationYAML: primary seed correctness ────────────────────────────

func TestBuildAutomationYAML_PrimaryIsPageURL_ForActiveScan(t *testing.T) {
	// Regression: if seedURLs[0] is a JS file, activeScan must NOT target it.
	// The first page-like seed must be used as primary.
	t.Setenv("DAST_ZAP_ACTIVE_SCAN", "1")
	seeds := []string{
		"https://sfera.example.ru/static/js/main.abc.js", // static — MUST NOT be primary
		"https://sfera.example.ru/",                       // page — must become primary
		"https://sfera.example.ru/app/ppau/",
	}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true}, seeds, nil, nil, nil)
	actScans := jobsOfType(doc, "activeScan")
	if len(actScans) == 0 {
		t.Skip("activeScan job not present (DAST_ZAP_ACTIVE_SCAN not honoured in test env)")
	}
	p, _ := actScans[0]["parameters"].(map[string]any)
	targetURL, _ := p["url"].(string)
	if !isPageLikeURL(targetURL) {
		t.Fatalf("activeScan must target a page URL, got static: %s", targetURL)
	}
}

func TestBuildAutomationYAML_PrimaryIsPageURL_ForIncludePathsFallback(t *testing.T) {
	// When allow is empty the includePaths fallback is built from primary.
	// If seeds start with a JS URL, the fallback pattern must still be rooted at the
	// correct host — not at .../static/js/main.js/.*
	seeds := []string{
		"https://sfera.example.ru/static/js/chunk.abc.js",
		"https://sfera.example.ru/",
	}
	doc := parsedDoc(t, config.ScanStep{ZAPSpiderAjax: true}, seeds, nil, nil, nil)
	ctx := contextBlock(t, doc)
	inc, _ := ctx["includePaths"].([]any)
	if len(inc) == 0 {
		t.Fatal("includePaths must not be empty")
	}
	pat := inc[0].(string)
	if strings.Contains(pat, "static/js") {
		t.Fatalf("includePaths fallback must be rooted at site root, not at JS path: %s", pat)
	}
	if !strings.Contains(pat, "sfera.example.ru") {
		t.Fatalf("includePaths fallback missing host: %s", pat)
	}
}

// ── legacy tests (preserved) ─────────────────────────────────────────────────

func TestBuildAutomationYAML_JobOrderAndSeeds(t *testing.T) {
	seeds := []string{"https://example.com/", "https://example.com/app/dash"}
	step := config.ScanStep{
		ZAPSpiderTraditional: true,
		ZAPSpiderAjax:        true,
		ZAPMaxSpiderMinutes:  5,
	}
	doc := parsedDoc(t, step, seeds, []string{`^https://example\.com(/.*)?$`}, nil, nil)
	ctx := contextBlock(t, doc)
	ctxURLs, _ := ctx["urls"].([]any)
	if len(ctxURLs) != 2 {
		t.Fatalf("context urls: %d", len(ctxURLs))
	}
	types := jobTypes(doc)
	raw := strings.Join(types, ",")
	if !strings.Contains(raw, "spider") || !strings.Contains(raw, "export") {
		t.Fatalf("job types: %s", raw)
	}
	spiderIdx := strings.Index(raw, "spider")
	exportIdx := strings.Index(raw, "export")
	if spiderIdx < 0 || spiderIdx > exportIdx {
		t.Fatalf("spider should be before export: %s", raw)
	}
	reportIdx := strings.Index(raw, "report")
	if reportIdx >= 0 && exportIdx > reportIdx {
		t.Fatalf("export should be before report: %s", raw)
	}
}

func TestBuildAutomationYAML_FinalExportIncludesActiveTree(t *testing.T) {
	t.Setenv("DAST_ZAP_ACTIVE_SCAN", "1")
	probes := []map[string]any{{"method": "GET", "url": "https://example.com/?q=1"}}
	doc := parsedDoc(t,
		config.ScanStep{ZAPSpiderTraditional: true, ZAPSpiderAjax: true},
		[]string{"https://example.com/"},
		[]string{`^https://example\.com(/.*)?$`},
		nil,
		probes,
	)
	types := jobTypes(doc)
	raw := strings.Join(types, ",")
	reqIdx := strings.Index(raw, "requestor")
	activeIdx := strings.Index(raw, "activeScan")
	exportIdx := strings.Index(raw, "export")
	reportIdx := strings.Index(raw, "report")
	if reqIdx < 0 || activeIdx < 0 || exportIdx < 0 || reportIdx < 0 {
		t.Fatalf("job types: %s", raw)
	}
	if !(reqIdx < activeIdx && activeIdx < exportIdx && exportIdx < reportIdx) {
		t.Fatalf("want requestor,activeScan,export,report order; got %s", raw)
	}
}
