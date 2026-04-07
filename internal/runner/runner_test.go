package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/storage"
)

func TestRun_minimalDummyPipeline(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "minimal-scan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseScanAsCode(data)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	sink := func(ts time.Time, level, msg string, _ map[string]string) {
		n++
	}
	jobID, err := Run(Options{
		WorkDir:        dir,
		ConfigYAML:     data,
		Config:         cfg,
		SkipZAPDocker:  true,
		ConfigFileDir:  filepath.Dir(filepath.Join("testdata", "minimal-scan.yaml")),
		OnProgress:     sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Fatalf("expected several progress callbacks, got %d", n)
	}
	final := filepath.Join(storage.JobRoot(dir, jobID), "findings", "findings-final.json")
	if _, err := os.Stat(final); err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(storage.OrchestratorLogPath(dir, jobID))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "Pipeline") {
		t.Fatalf("log: %s", string(logData))
	}
}

// Цепочка katana → zap → nuclei в одном job; внешние бинарни отключены — проверяем отсутствие паники и запись артефактов.
func TestRun_pipelineChainAllExternalSkipped(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "pipeline-all-skipped.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseScanAsCode(data)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := Run(Options{
		WorkDir:        dir,
		ConfigYAML:     data,
		Config:         cfg,
		SkipZAPDocker:  true,
		SkipNucleiCLI:  true,
		SkipKatanaCLI:  true,
		ConfigFileDir:  filepath.Join("testdata"),
	})
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(storage.JobRoot(dir, jobID), "findings", "findings-final.json")
	if _, err := os.Stat(final); err != nil {
		t.Fatal(err)
	}
}

// Задачи из REST кладут scan-as-code в work/jobs/<id>/config/ — относительные templatePaths должны находиться в корне репо.
func TestResolveTemplatePaths_fallbackRepoRoot(t *testing.T) {
	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	jobCfg := filepath.Join(workDir, "jobs", "j1", "config")
	if err := os.MkdirAll(jobCfg, 0o755); err != nil {
		t.Fatal(err)
	}
	tplDir := filepath.Join(root, "templates")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tplFile := filepath.Join(tplDir, "example-banner.yaml")
	if err := os.WriteFile(tplFile, []byte("id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := resolveTemplatePaths(jobCfg, []string{"templates/example-banner.yaml"}, workDir)
	if len(got) != 1 || got[0] != tplFile {
		t.Fatalf("got %v want %s", got, tplFile)
	}
}
