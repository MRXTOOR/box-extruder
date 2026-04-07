package nuclei

import (
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

func TestParseNucleiJSONL(t *testing.T) {
	raw := `{"template-id":"smoke","matched-at":"https://ex.test/path","host":"https://ex.test","info":{"name":"Smoke","severity":"high","description":"d"},"request":"GET /path HTTP/1.1\nHost: ex.test\n","response":"HTTP/1.1 404 Not Found\n\nmissing"}
`
	dedupe := config.DedupeConfig{LocationKey: "endpoint+method+paramsNormalized", ParamNormalization: "basic"}
	fs, ev, err := parseNucleiJSONL([]byte(raw), "ctx", dedupe)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || len(ev) != 1 {
		t.Fatalf("findings=%d evidence=%d", len(fs), len(ev))
	}
	if fs[0].RuleID != "nuclei-cli:smoke" || fs[0].Severity != model.SeverityHigh {
		t.Fatalf("%+v", fs[0])
	}
	if ev[0].StepType != model.StepNucleiCLI {
		t.Fatalf("stepType=%s", ev[0].StepType)
	}
	pl, ok := ev[0].Payload.(model.HTTPRequestResponsePayload)
	if !ok {
		t.Fatalf("payload type %T", ev[0].Payload)
	}
	if pl.URL != "https://ex.test/path" || pl.StatusCode != 404 || pl.Method != "GET" {
		t.Fatalf("%+v", pl)
	}
}

func TestRunCLI_requiresTargetsOrList(t *testing.T) {
	_, _, err := RunCLI(CLIOptions{TemplatePaths: []string{"x"}})
	if err == nil || !strings.Contains(err.Error(), "Targets or ListFile") {
		t.Fatalf("got %v", err)
	}
}

func TestRunCLI_rejectsBothTargetsAndList(t *testing.T) {
	_, _, err := RunCLI(CLIOptions{
		Targets:       []string{"https://a"},
		ListFile:      "/tmp/x",
		TemplatePaths: []string{"y"},
	})
	if err == nil || !strings.Contains(err.Error(), "Targets or ListFile") {
		t.Fatalf("got %v", err)
	}
}

func TestParseNucleiJSONL_skipsEmptyMatched(t *testing.T) {
	raw := `{"template-id":"x","info":{"name":"n"}}`
	fs, ev, err := parseNucleiJSONL([]byte(raw), "ctx", config.DedupeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 || len(ev) != 0 {
		t.Fatalf("expected skip, got f=%d e=%d", len(fs), len(ev))
	}
}
