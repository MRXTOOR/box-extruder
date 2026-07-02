package runner

import (
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

// ── normalizeDiscoveryURL ─────────────────────────────────────────────────────

func TestNormalizeDiscoveryURL_PreserveQuery(t *testing.T) {
	raw := "https://example.com/api?searchName=abc"
	pathOnly, _ := normalizeDiscoveryURL(raw, false)
	withQ, _ := normalizeDiscoveryURL(raw, true)
	if pathOnly != "https://example.com/api" {
		t.Fatalf("path only: %q", pathOnly)
	}
	if withQ != raw {
		t.Fatalf("with query: %q", withQ)
	}
}

func TestNormalizeDiscoveryURL_StripFragment(t *testing.T) {
	raw := "https://example.com/page#section"
	got, ok := normalizeDiscoveryURL(raw, false)
	if !ok {
		t.Fatal("should be ok")
	}
	if got != "https://example.com/page" {
		t.Fatalf("got %q, want no fragment", got)
	}
}

func TestNormalizeDiscoveryURL_EmptyPath(t *testing.T) {
	got, ok := normalizeDiscoveryURL("https://example.com", false)
	if !ok {
		t.Fatal("should be ok")
	}
	if got != "https://example.com/" {
		t.Fatalf("empty path should become /: %q", got)
	}
}

func TestNormalizeDiscoveryURL_InvalidURL(t *testing.T) {
	_, ok := normalizeDiscoveryURL("://bad", false)
	if ok {
		t.Fatal("expected !ok for invalid URL")
	}
}

// ── harvestHTTPURLsFromFindings ───────────────────────────────────────────────

func makeHTTPFinding(evID, rawURL string) (model.Finding, model.Evidence) {
	f := model.Finding{EvidenceRefs: []string{evID}}
	ev := model.Evidence{
		EvidenceID: evID,
		Type:       model.EvidenceHTTPRequestResponse,
		Payload: model.HTTPRequestResponsePayload{
			Method: "GET",
			URL:    rawURL,
		},
	}
	return f, ev
}

func TestHarvestHTTPURLs_BasicDedup(t *testing.T) {
	f1, ev1 := makeHTTPFinding("e1", "https://example.com/api?q=1")
	f2, ev2 := makeHTTPFinding("e2", "https://example.com/api?q=1")
	evMap := map[string]model.Evidence{ev1.EvidenceID: ev1, ev2.EvidenceID: ev2}
	got := harvestHTTPURLsFromFindings([]model.Finding{f1, f2}, evMap, true)
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped URL, got %d: %v", len(got), got)
	}
}

func TestHarvestHTTPURLs_PreservesQuery(t *testing.T) {
	cfg := &config.ScanAsCode{
		Budgets: config.Budgets{
			Discovery: config.DiscoveryBudget{PreserveQuery: true},
		},
	}
	f, ev := makeHTTPFinding("e1", "https://example.com/x?a=1")
	urls := harvestHTTPURLsFromFindings([]model.Finding{f},
		map[string]model.Evidence{ev.EvidenceID: ev},
		discoveryPreserveQuery(cfg))
	if len(urls) != 1 || urls[0] != "https://example.com/x?a=1" {
		t.Fatalf("got %v", urls)
	}
}

func TestHarvestHTTPURLs_StripsQueryWhenNotPreserved(t *testing.T) {
	f, ev := makeHTTPFinding("e1", "https://example.com/api?q=foo")
	urls := harvestHTTPURLsFromFindings([]model.Finding{f},
		map[string]model.Evidence{ev.EvidenceID: ev}, false)
	if len(urls) != 1 || urls[0] != "https://example.com/api" {
		t.Fatalf("got %v", urls)
	}
}

func TestHarvestHTTPURLs_SkipsAttackPayloads(t *testing.T) {
	// These are ZAP active-scan probe URLs that must not be fed to Nuclei.
	attackURLs := []string{
		"https://example.com/api?q=%27+OR+%271%27%3D%271",
		"https://example.com/api?q=%27+AND+%271%27%3D%272",
		"https://example.com/search?x=<script>alert(1)</script>",
		"https://example.com/page?q=javascript:alert(1)",
	}
	var findings []model.Finding
	evMap := make(map[string]model.Evidence)
	for i, u := range attackURLs {
		evID := "ev" + string(rune('0'+i))
		f, ev := makeHTTPFinding(evID, u)
		findings = append(findings, f)
		evMap[evID] = ev
	}
	got := harvestHTTPURLsFromFindings(findings, evMap, true)
	if len(got) != 0 {
		t.Fatalf("attack payload URLs must be filtered out, got: %v", got)
	}
}

func TestHarvestHTTPURLs_PassesLegitimateAPIURLs(t *testing.T) {
	// Real authenticated API endpoints like those in the Sfera reference scan.
	legitimate := []string{
		"https://sfera.release.dev.sfera-t1.ru/api/tenant/v1/user/routes",
		"https://sfera.release.dev.sfera-t1.ru/api/profile/admin/v1/users/current",
		"https://sfera.release.dev.sfera-t1.ru/api/common/widgets/v1/maintenance-mode?app=PPOR",
		"https://sfera.release.dev.sfera-t1.ru/service/notifications/api/v1/ui-resource-strings?component=chatBot",
		"https://sfera.release.dev.sfera-t1.ru/app/home-page/api/tenant/v1/user/applications/menu",
	}
	var findings []model.Finding
	evMap := make(map[string]model.Evidence)
	for i, u := range legitimate {
		evID := "ev" + string(rune('a'+i))
		f, ev := makeHTTPFinding(evID, u)
		findings = append(findings, f)
		evMap[evID] = ev
	}
	got := harvestHTTPURLsFromFindings(findings, evMap, true)
	if len(got) != len(legitimate) {
		t.Fatalf("all legitimate URLs should pass, got %d/%d: %v", len(got), len(legitimate), got)
	}
}

// ── mergeSeedURLs ─────────────────────────────────────────────────────────────

func TestMergeSeedURLs_Dedup(t *testing.T) {
	base := []string{"https://a/", "https://b/"}
	extra := []string{"https://b/", "https://c/"}
	got := mergeSeedURLs(base, extra)
	if len(got) != 3 {
		t.Fatalf("want 3 deduped URLs, got %d: %v", len(got), got)
	}
}

func TestMergeSeedURLs_PreservesBaseOrder(t *testing.T) {
	base := []string{"https://a/", "https://b/"}
	extra := []string{"https://c/"}
	got := mergeSeedURLs(base, extra)
	if got[0] != "https://a/" || got[1] != "https://b/" || got[2] != "https://c/" {
		t.Fatalf("wrong order: %v", got)
	}
}

func TestMergeSeedURLs_EmptyInputs(t *testing.T) {
	if got := mergeSeedURLs(nil, nil); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
	if got := mergeSeedURLs([]string{"https://a/"}, nil); len(got) != 1 {
		t.Fatalf("expected 1, got %v", got)
	}
}

// ── nucleiBasesFromTargets ────────────────────────────────────────────────────

func TestNucleiBasesFromTargets(t *testing.T) {
	cfg := &config.ScanAsCode{
		Targets: []config.Target{{
			BaseURL:     "https://example.com",
			StartPoints: []string{"https://example.com/app/dash", "https://example.com"},
		}},
	}
	bases := nucleiBasesFromTargets(cfg)
	if len(bases) != 2 {
		t.Fatalf("want 2 bases (deduped), got %v", bases)
	}
}

func TestNucleiBasesFromTargets_MultipleTargets(t *testing.T) {
	cfg := &config.ScanAsCode{
		Targets: []config.Target{
			{BaseURL: "https://a.example.com"},
			{BaseURL: "https://b.example.com", StartPoints: []string{"https://b.example.com/app"}},
		},
	}
	bases := nucleiBasesFromTargets(cfg)
	if len(bases) != 3 {
		t.Fatalf("want 3 bases, got %v", bases)
	}
}

// ── nucleiCLITargetLines ──────────────────────────────────────────────────────

func TestNucleiCLITargetLines_CapsAtBudget(t *testing.T) {
	cfg := &config.ScanAsCode{
		Budgets: config.Budgets{
			Discovery: config.DiscoveryBudget{MaxURLs: 5},
		},
	}
	bases := []string{"https://example.com/"}
	feed := make([]string, 100)
	for i := range feed {
		feed[i] = "https://example.com/page"
	}
	got := nucleiCLITargetLines(cfg, bases, feed, true)
	if len(got) > 5 {
		t.Fatalf("expected at most 5 targets (cap), got %d", len(got))
	}
}

func TestNucleiCLITargetLines_ExcludesFeedWhenFlagFalse(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	bases := []string{"https://example.com/"}
	feed := []string{"https://example.com/api/found"}
	got := nucleiCLITargetLines(&cfg, bases, feed, false)
	if len(got) != 1 || got[0] != "https://example.com/" {
		t.Fatalf("feed should be excluded when includeDiscoveredURLs=false: %v", got)
	}
}

// ── feedAppend ────────────────────────────────────────────────────────────────

func TestFeedAppend_Dedup(t *testing.T) {
	seen := make(map[string]struct{})
	var feed []string
	feedAppend(seen, &feed, []string{"https://a/", "https://b/"})
	feedAppend(seen, &feed, []string{"https://b/", "https://c/"})
	if len(feed) != 3 {
		t.Fatalf("expected 3 unique URLs, got %d: %v", len(feed), feed)
	}
}

func TestFeedAppend_SkipsGarbage(t *testing.T) {
	seen := make(map[string]struct{})
	var feed []string
	feedAppend(seen, &feed, []string{
		"https://example.com/api/users",
		"https://example.com/%PUBLIC_URL%/static/main.js",
		"https://example.com/manifest.json",
	})
	if len(feed) != 1 || feed[0] != "https://example.com/api/users" {
		t.Fatalf("garbage URLs must be skipped: %v", feed)
	}
}

func TestHarvestHTTPURLs_SkipsGarbage(t *testing.T) {
	f, ev := makeHTTPFinding("e1", "https://example.com/%PUBLIC_URL%/x")
	got := harvestHTTPURLsFromFindings([]model.Finding{f},
		map[string]model.Evidence{ev.EvidenceID: ev}, true)
	if len(got) != 0 {
		t.Fatalf("PUBLIC_URL must be filtered: %v", got)
	}
}

func TestFeedAppend_SkipsEmpty(t *testing.T) {
	seen := make(map[string]struct{})
	var feed []string
	feedAppend(seen, &feed, []string{"", "  ", "https://x.com/"})
	if len(feed) != 1 {
		t.Fatalf("expected 1, got %d: %v", len(feed), feed)
	}
}
