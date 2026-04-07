package katana

import (
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

func TestParseKatanaJSONL(t *testing.T) {
	raw := `{"request":{"method":"GET","endpoint":"https://ex.test/a","tag":"a","attribute":"href","source":"https://ex.test/"},"response":{"status_code":200}}
`
	dedupe := config.DedupeConfig{LocationKey: "endpoint+method+paramsNormalized", ParamNormalization: "basic"}
	fs, ev, err := parseKatanaJSONL([]byte(raw), "ctx", dedupe)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || len(ev) != 1 {
		t.Fatalf("findings=%d evidence=%d", len(fs), len(ev))
	}
	if fs[0].RuleID != "katana:discovered-url" || fs[0].Severity != model.SeverityInfo {
		t.Fatalf("%+v", fs[0])
	}
	if ev[0].StepType != model.StepKatana {
		t.Fatalf("stepType=%s", ev[0].StepType)
	}
	pl, ok := ev[0].Payload.(model.HTTPRequestResponsePayload)
	if !ok {
		t.Fatalf("payload type %T", ev[0].Payload)
	}
	if pl.URL != "https://ex.test/a" || pl.Method != "GET" || pl.StatusCode != 200 {
		t.Fatalf("%+v", pl)
	}
}

func TestParseKatanaJSONL_skipsEmptyEndpoint(t *testing.T) {
	raw := `{"request":{"method":"GET"},"response":{}}`
	fs, ev, err := parseKatanaJSONL([]byte(raw), "ctx", config.DedupeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 || len(ev) != 0 {
		t.Fatalf("expected skip, got f=%d e=%d", len(fs), len(ev))
	}
}
