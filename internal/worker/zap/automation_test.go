package zap

import (
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/config"
)

func TestUseAutomation(t *testing.T) {
	if UseAutomation(config.ScanStep{}) {
		t.Fatal("empty step should not force automation")
	}
	if !UseAutomation(config.ScanStep{ZAPSpiderAjax: true}) {
		t.Fatal()
	}
	if !UseAutomation(config.ScanStep{ZAPAutomationFramework: true}) {
		t.Fatal()
	}
	if !UseAutomation(config.ScanStep{ZAPAutomationFile: "x.yaml"}) {
		t.Fatal()
	}
}

func TestBuildAutomationYAML_spiderAndAjax(t *testing.T) {
	step := config.ScanStep{
		ZAPSpiderAjax:         true,
		ZAPSpiderTraditional:  true,
		ZAPMaxSpiderMinutes:   2,
		ZAPPassiveWaitSeconds: 30,
	}
	b, err := buildAutomationYAML("https://example.com", []string{`^https://example\.com/.*`}, nil, step, "/zap/wrk", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "spiderAjax") || !strings.Contains(s, "type: spider") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "traditional-json") {
		t.Fatal(s)
	}
}

func TestBuildAutomationYAML_authReplacer(t *testing.T) {
	step := config.ScanStep{ZAPSpiderTraditional: true, ZAPSpiderAjax: false}
	b, err := buildAutomationYAML("https://example.com", nil, nil, step, "/zap/wrk", map[string]string{
		"Authorization": "Bearer test-token",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "type: replacer") || !strings.Contains(s, "req_header") ||
		!strings.Contains(s, "Authorization") || !strings.Contains(s, "replacementString") ||
		!strings.Contains(s, "Bearer test-token") {
		t.Fatal(s)
	}
}

func TestRemapLocalhostForZAPDocker(t *testing.T) {
	t.Setenv("DAST_ZAP_LOCAL", "") // docker path
	u, allow, extra := remapLocalhostForZAPDocker("http://127.0.0.1:3000/", []string{`^http://127\.0\.0\.1:3000/.*`})
	if u != "http://host.docker.internal:3000/" {
		t.Fatalf("url: %q", u)
	}
	if allow[0] != `^http://host\.docker\.internal:3000/.*` {
		t.Fatalf("allow: %q", allow[0])
	}
	if len(extra) != 1 || extra[0] != "--add-host=host.docker.internal:host-gateway" {
		t.Fatalf("extra: %v", extra)
	}
}

func TestRemapLocalhostForZAPDocker_localZAPNoop(t *testing.T) {
	t.Setenv("DAST_ZAP_LOCAL", "1")
	u, allow, extra := remapLocalhostForZAPDocker("http://127.0.0.1:3000/", []string{"x"})
	if u != "http://127.0.0.1:3000/" || allow[0] != "x" || extra != nil {
		t.Fatalf("got %q %v %v", u, allow, extra)
	}
}

func TestBuildAutomationYAML_ajaxOnly(t *testing.T) {
	step := config.ScanStep{ZAPSpiderAjax: true, ZAPSpiderTraditional: false}
	b, err := buildAutomationYAML("https://ex.com", nil, nil, step, "/tmp/out", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "type: spider\n") && strings.Contains(s, "spiderAjax") {
		// "type: spider" appears in spiderAjax line too - check traditional spider block
		if !strings.Contains(s, "spiderAjax") {
			t.Fatal(s)
		}
	}
	if strings.Contains(s, "- type: spider") || strings.Contains(s, "type: spider") {
		// should not have standalone spider job before passive - check no "- type: spider" without Ajax
		idx := strings.Index(s, "spiderAjax")
		pre := s[:idx]
		if strings.Contains(pre, "type: spider") && !strings.Contains(pre, "spiderAjax") {
			// yaml has "type: spider" for traditional - pre before ajax should lack "- type: spider" as first job
			if strings.Contains(pre, "- type: spider") {
				t.Fatal("traditional spider should be omitted")
			}
		}
	}
}
