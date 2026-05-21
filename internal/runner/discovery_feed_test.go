package runner

import (
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

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

func TestHarvestPreservesQueryFromConfig(t *testing.T) {
	cfg := &config.ScanAsCode{
		Budgets: config.Budgets{
			Discovery: config.DiscoveryBudget{PreserveQuery: true},
		},
	}
	evID := "e1"
	f := model.Finding{EvidenceRefs: []string{evID}}
	ev := map[string]model.Evidence{
		evID: {
			Type: model.EvidenceHTTPRequestResponse,
			Payload: model.HTTPRequestResponsePayload{
				URL: "https://example.com/x?a=1",
			},
		},
	}
	urls := harvestHTTPURLsFromFindings([]model.Finding{f}, ev, discoveryPreserveQuery(cfg))
	if len(urls) != 1 || urls[0] != "https://example.com/x?a=1" {
		t.Fatalf("got %v", urls)
	}
}
