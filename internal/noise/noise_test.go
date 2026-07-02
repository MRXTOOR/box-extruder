package noise

import (
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

func TestApply_SuppressesRule10027(t *testing.T) {
	cfg := config.ScanAsCode{
		Noise: config.NoiseControl{
			Suppression: config.SuppressionConfig{
				Exclude: []config.SuppressionRule{{
					RuleID: "10027",
					Reason: "SPA CRA boilerplate comments",
				}},
			},
		},
	}
	in := []model.Finding{{
		RuleID:      "10027",
		LocationKey: "GET https://app.example/",
		Title:       "Information Disclosure - Suspicious Comments",
	}}
	out := Apply(cfg, in, nil)
	if len(out) != 1 {
		t.Fatalf("finding kept: %d", len(out))
	}
	if out[0].LifecycleStatus != model.LifecycleFalsePositiveSuppressed {
		t.Fatalf("status: %v", out[0].LifecycleStatus)
	}
}

func TestApply_DedupesPassiveZAPByHost(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	in := []model.Finding{
		{RuleID: "10035", LocationKey: "GET https://app.example/app/a", Title: "CSP"},
		{RuleID: "10035", LocationKey: "GET https://app.example/app/b", Title: "CSP"},
		{RuleID: "10035", LocationKey: "GET https://other.example/", Title: "CSP"},
	}
	out := Apply(cfg, in, nil)
	if len(out) != 2 {
		t.Fatalf("want 2 after host dedupe, got %d: %+v", len(out), out)
	}
}
