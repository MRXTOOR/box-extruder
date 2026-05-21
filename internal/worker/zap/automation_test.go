package zap

import (
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/config"
	"gopkg.in/yaml.v3"
)

func TestBuildAutomationYAML_JobOrderAndSeeds(t *testing.T) {
	seeds := []string{"https://example.com/", "https://example.com/app/dash"}
	step := config.ScanStep{
		ZAPSpiderTraditional: true,
		ZAPSpiderAjax:        true,
		ZAPMaxSpiderMinutes:  5,
	}
	yamlBytes, err := buildAutomationYAML(seeds, []string{`^https://example\.com(/.*)?$`}, step, "/zap/wrk", nil, nil, "/zap/wrk/zap-export-urls.txt")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(yamlBytes, &doc); err != nil {
		t.Fatal(err)
	}
	env, _ := doc["env"].(map[string]any)
	ctxs, _ := env["contexts"].([]any)
	ctx0, _ := ctxs[0].(map[string]any)
	urls, _ := ctx0["urls"].([]any)
	if len(urls) != 2 {
		t.Fatalf("context urls: %d", len(urls))
	}
	jobs, _ := doc["jobs"].([]any)
	types := make([]string, 0, len(jobs))
	for _, j := range jobs {
		m, _ := j.(map[string]any)
		types = append(types, m["type"].(string))
	}
	raw := strings.Join(types, ",")
	if !strings.Contains(raw, "spider") || !strings.Contains(raw, "export") {
		t.Fatalf("job types: %s", raw)
	}
	spiderIdx := strings.Index(raw, "spider")
	exportIdx := strings.Index(raw, "export")
	reqIdx := strings.Index(raw, "requestor")
	if exportIdx < 0 {
		t.Fatal("missing export job")
	}
	if reqIdx >= 0 && exportIdx > reqIdx {
		t.Fatalf("export should be before requestor: %s", raw)
	}
	if spiderIdx < 0 || spiderIdx > exportIdx {
		t.Fatalf("spider should be before export: %s", raw)
	}
}
