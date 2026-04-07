package runner

import (
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

func TestHarvestHTTPURLsFromFindings(t *testing.T) {
	ev := map[string]model.Evidence{
		"e1": {
			EvidenceID: "e1",
			Type:       model.EvidenceHTTPRequestResponse,
			Payload: model.HTTPRequestResponsePayload{
				URL: "https://a/x",
			},
		},
	}
	fs := []model.Finding{
		{EvidenceRefs: []string{"e1"}},
		{EvidenceRefs: []string{"e1"}},
	}
	got := harvestHTTPURLsFromFindings(fs, ev)
	if len(got) != 1 || got[0] != "https://a/x" {
		t.Fatalf("%v", got)
	}
}

func TestFeedAppend_dedup(t *testing.T) {
	seen := make(map[string]struct{})
	var feed []string
	feedAppend(seen, &feed, []string{"https://a", "https://b", "https://a"})
	if len(feed) != 2 {
		t.Fatalf("%v", feed)
	}
}

func TestNucleiCLITargetLines_capAndInclude(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	cfg.Scope.MaxURLs = 4
	bases := []string{"https://t1/"}
	feed := []string{"https://t1/a", "https://t1/b", "https://t2/z", "https://t3/w"}
	out := nucleiCLITargetLines(&cfg, bases, feed, true)
	if len(out) != 4 {
		t.Fatalf("want cap 4, got %d: %v", len(out), out)
	}
	if out[0] != "https://t1/" {
		t.Fatalf("%v", out)
	}
}

func TestNucleiBuiltinBases_originsOnly(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	cfg.Scope.MaxURLs = 10
	bases := []string{"https://ex.com"}
	feed := []string{"https://ex.com/path1", "https://ex.com/path2", "https://other.dev/"}
	out := nucleiBuiltinBases(&cfg, bases, feed, true)
	if len(out) != 2 {
		t.Fatalf("want 2 origins, got %d: %v", len(out), out)
	}
}
