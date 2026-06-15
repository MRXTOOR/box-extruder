package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactYAMLSecrets(t *testing.T) {
	in := []byte("login: admin\npassword: secret123\ntarget: https://x.test\n")
	out := redactYAMLSecrets(in)
	if strings.Contains(string(out), "secret123") {
		t.Fatal("password not redacted")
	}
	if !strings.Contains(string(out), "[СКРЫТО]") {
		t.Fatal("expected redaction marker")
	}
}

func TestBuildScanDump_minimalJob(t *testing.T) {
	dir := t.TempDir()
	jobID := "test-job-1"
	root := JobRoot(dir, jobID)
	_ = InitJobDirs(dir, jobID)
	_ = os.WriteFile(filepath.Join(root, "events", "events.jsonl"), []byte(`{"level":"info","message":"start"}`+"\n"), 0o644)
	_ = AppendOrchestratorLog(dir, jobID, "orchestrator ok")

	out := filepath.Join(t.TempDir(), "out.zip")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := BuildScanDump(dir, jobID, f, DefaultDumpMaxBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	st, err := os.Stat(out)
	if err != nil || st.Size() < 50 {
		t.Fatalf("expected non-empty zip, got %v err=%v", st, err)
	}
}
