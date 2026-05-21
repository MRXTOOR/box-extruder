package webscan

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuildScanYAML_PipelineAndDiscovery(t *testing.T) {
	yamlBytes, err := BuildScanYAML(CreateOptions{
		Target: "https://sfera.example/app/dashboard",
		JobID:  "test-job",
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(yamlBytes, &doc); err != nil {
		t.Fatal(err)
	}
	budgets, _ := doc["budgets"].(map[string]any)
	disc, _ := budgets["discovery"].(map[string]any)
	if disc["preserveQuery"] != true {
		t.Fatalf("preserveQuery: %v", disc["preserveQuery"])
	}
	scan, _ := doc["scan"].(map[string]any)
	plan, _ := scan["plan"].([]any)
	if len(plan) != 3 {
		t.Fatalf("plan steps: want 3 (katana,zap,nuclei), got %d", len(plan))
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
	if s2["stepType"] != "nucleiTemplates" {
		t.Fatalf("step2: %v", s2["stepType"])
	}
	raw := string(yamlBytes)
	if !strings.Contains(raw, "preserveQuery") {
		t.Fatal("missing preserveQuery in yaml")
	}
}
