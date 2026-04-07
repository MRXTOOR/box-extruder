package config

import (
	"strings"
	"testing"
)

func TestParseScanAsCode_minimal(t *testing.T) {
	y := `
version: "1.0"
job: { name: x }
targets:
  - type: web
    baseUrl: https://a.example
`
	c, err := ParseScanAsCode([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if c.Targets[0].BaseURL != "https://a.example" {
		t.Fatal(c.Targets[0].BaseURL)
	}
	if c.Version != "1.0" {
		t.Fatal(c.Version)
	}
}

func TestParseScanAsCode_rejectsEmptyTargets(t *testing.T) {
	y := `version: "1.0"
job: { name: x }
targets: []
`
	_, err := ParseScanAsCode([]byte(y))
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected targets error, got %v", err)
	}
}

func TestEffectivePlan_presets(t *testing.T) {
	fast := ScanAsCode{Scan: Scan{Preset: "Fast"}}
	if len(EffectivePlan(fast)) != 3 {
		t.Fatalf("Fast: got %d steps", len(EffectivePlan(fast)))
	}
	std := ScanAsCode{Scan: Scan{Preset: "Standard"}}
	if len(EffectivePlan(std)) != 4 {
		t.Fatalf("Standard: got %d steps", len(EffectivePlan(std)))
	}
	deep := ScanAsCode{Scan: Scan{Preset: "Deep"}}
	if len(EffectivePlan(deep)) != 4 {
		t.Fatalf("Deep: got %d steps", len(EffectivePlan(deep)))
	}
}

func TestEffectivePlan_explicitOverridesPreset(t *testing.T) {
	c := ScanAsCode{
		Scan: Scan{
			Preset: "Fast",
			Plan: []ScanStep{
				{StepType: "crawl", Enabled: true},
			},
		},
	}
	if len(EffectivePlan(c)) != 1 {
		t.Fatal(len(EffectivePlan(c)))
	}
}

func TestMergeDefaults_partialNoiseControlRestoresFalsePositive(t *testing.T) {
	y := `
version: "1.0"
job: { name: x }
targets:
  - type: web
    baseUrl: https://a.example
noiseControl:
  dedupe:
    locationKey: "endpoint+method+paramsNormalized"
    paramNormalization: "basic"
`
	c, err := ParseScanAsCode([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if c.Noise.FalsePositive.ProgressiveConfirmation == nil {
		t.Fatal("expected progressiveConfirmation merged from defaults")
	}
	if !*c.Noise.FalsePositive.ProgressiveConfirmation {
		t.Fatal("expected progressiveConfirmation true")
	}
	if !c.EffectiveProgressiveConfirmation() {
		t.Fatal("EffectiveProgressiveConfirmation should be true")
	}
}

func TestReportIncludeEvidence(t *testing.T) {
	tFalse := false
	tTrue := true
	cases := []struct {
		name string
		c    ScanAsCode
		want bool
	}{
		{"nil docx defaults true", ScanAsCode{Outputs: Outputs{}}, true},
		{"explicit true", ScanAsCode{Outputs: Outputs{IncludeEvidence: &tTrue}}, true},
		{"explicit false", ScanAsCode{Outputs: Outputs{IncludeEvidence: &tFalse}}, false},
		{"docx includeEvidence true", ScanAsCode{Outputs: Outputs{Docx: &DocxOut{IncludeEvidence: true}}}, true},
		{"docx without includeEvidence", ScanAsCode{Outputs: Outputs{Docx: &DocxOut{}}}, false},
		{"explicit overrides docx off", ScanAsCode{Outputs: Outputs{IncludeEvidence: &tTrue, Docx: &DocxOut{}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.ReportIncludeEvidence(); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestResolveSecretRef(t *testing.T) {
	t.Setenv("DAST_UNIT_X", "tok")
	v, err := ResolveSecretRef("secret://DAST_UNIT_X")
	if err != nil || v != "tok" {
		t.Fatalf("%q %v", v, err)
	}
	_, err = ResolveSecretRef("secret://DAST_MISSING_XYZ")
	if err == nil {
		t.Fatal("expected error")
	}
}
