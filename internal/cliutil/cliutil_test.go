package cliutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/storage"
)

func TestResolveJobID_last(t *testing.T) {
	root := t.TempDir()
	if err := storage.InitJobDirs(root, "only"); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteJob(root, &model.Job{JobID: "only", Status: model.JobQueued}); err != nil {
		t.Fatal(err)
	}
	id, err := ResolveJobID(root, "last")
	if err != nil || id != "only" {
		t.Fatalf("%q %v", id, err)
	}
}

func TestPrintOrchestratorLog_once(t *testing.T) {
	root := t.TempDir()
	jobID := "j"
	if err := storage.InitJobDirs(root, jobID); err != nil {
		t.Fatal(err)
	}
	if err := storage.AppendOrchestratorLog(root, jobID, "hello"); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := PrintOrchestratorLog(f, root, jobID, false, 0); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(tmp)
	if len(b) == 0 || !strings.Contains(string(b), "hello") {
		t.Fatalf("%q", b)
	}
}
