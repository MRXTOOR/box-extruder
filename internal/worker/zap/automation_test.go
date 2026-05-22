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
	yamlBytes, err := buildAutomationYAML(seeds, []string{`^https://example\.com(/.*)?$`}, step, "/zap/wrk", nil, nil)
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
	if exportIdx < 0 {
		t.Fatal("missing export job")
	}
	if spiderIdx < 0 || spiderIdx > exportIdx {
		t.Fatalf("spider should be before export: %s", raw)
	}
	reportIdx := strings.Index(raw, "report")
	if reportIdx >= 0 && exportIdx > reportIdx {
		t.Fatalf("export should be before report: %s", raw)
	}
}

func TestBuildAutomationYAML_FinalExportIncludesActiveTree(t *testing.T) {
	t.Setenv("DAST_ZAP_ACTIVE_SCAN", "1")
	yamlBytes, err := buildAutomationYAML(
		[]string{"https://example.com/"},
		[]string{`^https://example\.com(/.*)?$`},
		config.ScanStep{ZAPSpiderTraditional: true, ZAPSpiderAjax: true},
		"/zap/wrk",
		nil,
		[]map[string]any{{"method": "GET", "url": "https://example.com/?q=1"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(yamlBytes, &doc); err != nil {
		t.Fatal(err)
	}
	jobs, _ := doc["jobs"].([]any)
	types := make([]string, 0, len(jobs))
	for _, j := range jobs {
		m, _ := j.(map[string]any)
		types = append(types, m["type"].(string))
	}
	raw := strings.Join(types, ",")
	reqIdx := strings.Index(raw, "requestor")
	activeIdx := strings.Index(raw, "activeScan")
	exportIdx := strings.Index(raw, "export")
	reportIdx := strings.Index(raw, "report")
	if reqIdx < 0 || activeIdx < 0 || exportIdx < 0 || reportIdx < 0 {
		t.Fatalf("job types: %s", raw)
	}
	if !(reqIdx < activeIdx && activeIdx < exportIdx && exportIdx < reportIdx) {
		t.Fatalf("want requestor,activeScan,export,report order; got %s", raw)
	}
}
