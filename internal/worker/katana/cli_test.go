package katana

import (
	"fmt"
	"testing"

	"github.com/box-extruder/dast/internal/config"
)

func TestParseKatanaJSONL_IgnoresBrowserLauncherLines(t *testing.T) {
	raw := []byte(`[launcher.Browser] Downloading chromium
{"request":{"method":"GET","endpoint":"https://example.com/a"},"response":{"status_code":200}}
`)
	f, e, err := parseKatanaJSONL(raw, "ctx", config.DedupeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || len(e) != 1 {
		t.Fatalf("want 1 finding, got f=%d e=%d", len(f), len(e))
	}
}

func TestHeadlessSetupLikely(t *testing.T) {
	if !HeadlessSetupLikely(fmt.Errorf("katana headless: browser setup finished")) {
		t.Fatal("expected headless likely")
	}
	if HeadlessSetupLikely(nil) {
		t.Fatal("nil should be false")
	}
}
