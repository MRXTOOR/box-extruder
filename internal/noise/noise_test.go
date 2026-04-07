package noise

import (
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

func TestBuildLocationKeyFromHTTP(t *testing.T) {
	d := config.DedupeConfig{ParamNormalization: "basic"}
	k := BuildLocationKeyFromHTTP(d, "GET", "https://ex.com/a?z=2&b=1")
	k2 := BuildLocationKeyFromHTTP(d, "GET", "https://ex.com/a?b=1&z=2")
	if k != k2 {
		t.Fatalf("order invariant: %q vs %q", k, k2)
	}
}

func TestApply_dedupeSameLocationAndRule(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	now := time.Now().UTC()
	in := []model.Finding{
		{FindingID: "a", RuleID: "r1", LocationKey: "GET https://x/p", Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleDetected, FirstSeenAt: now, LastSeenAt: now},
		{FindingID: "b", RuleID: "r1", LocationKey: "GET https://x/p", Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleDetected, FirstSeenAt: now, LastSeenAt: now},
	}
	out := Apply(cfg, in, map[string]model.Evidence{})
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
}

func TestApply_excludeCategory(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	cfg.Noise.Suppression.Exclude = []config.SuppressionRule{
		{Category: "NoiseCat", Reason: "policy"},
	}
	now := time.Now().UTC()
	in := []model.Finding{
		{FindingID: "x", RuleID: "r", Category: "NoiseCat", LocationKey: "GET https://x/", Severity: model.SeverityLow, LifecycleStatus: model.LifecycleDetected, FirstSeenAt: now, LastSeenAt: now},
	}
	out := Apply(cfg, in, map[string]model.Evidence{})
	if len(out) != 1 || out[0].LifecycleStatus != model.LifecycleFalsePositiveSuppressed {
		t.Fatalf("%+v", out)
	}
	if out[0].SuppressionReason != "policy" {
		t.Fatal(out[0].SuppressionReason)
	}
}

func TestApply_progressiveConfirmsWithHTTPEvidenceLow(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	cfg.Budgets.Verification.EvidenceThreshold = "low"
	now := time.Now().UTC()
	evID := "ev-1"
	in := []model.Finding{{
		FindingID: "a", RuleID: "r1", LocationKey: "GET http://x/p", Severity: model.SeverityHigh,
		LifecycleStatus: model.LifecycleDetected, FirstSeenAt: now, LastSeenAt: now,
		EvidenceRefs: []string{evID},
	}}
	ev := map[string]model.Evidence{
		evID: {
			EvidenceID: evID,
			Type:       model.EvidenceHTTPRequestResponse,
			Payload:    model.HTTPRequestResponsePayload{Method: "GET", URL: "http://x/p"},
		},
	}
	out := Apply(cfg, in, ev)
	if len(out) != 1 || out[0].LifecycleStatus != model.LifecycleConfirmed {
		t.Fatalf("got %+v", out)
	}
}

func TestApply_mediumRequiresStrongerEvidence(t *testing.T) {
	cfg := config.DefaultScanAsCode()
	cfg.Budgets.Verification.EvidenceThreshold = "medium"
	now := time.Now().UTC()
	evID := "ev-1"
	in := []model.Finding{{
		FindingID: "a", RuleID: "r1", LocationKey: "GET http://x/p", Severity: model.SeverityHigh,
		LifecycleStatus: model.LifecycleDetected, FirstSeenAt: now, LastSeenAt: now,
		EvidenceRefs: []string{evID},
	}}
	ev := map[string]model.Evidence{
		evID: {
			EvidenceID: evID,
			Type:       model.EvidenceHTTPRequestResponse,
			Payload:    model.HTTPRequestResponsePayload{Method: "GET", URL: "http://x/p"},
		},
	}
	out := Apply(cfg, in, ev)
	if len(out) != 1 || out[0].LifecycleStatus != model.LifecycleUnconfirmed {
		t.Fatalf("expected unconfirmed without status/body, got %+v", out[0].LifecycleStatus)
	}
}
