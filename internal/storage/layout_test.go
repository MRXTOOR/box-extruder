package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestInitJobDirs_WriteReadJob(t *testing.T) {
	dir := t.TempDir()
	jobID := "test-job-id"
	if err := InitJobDirs(dir, jobID); err != nil {
		t.Fatal(err)
	}
	j := &model.Job{JobID: jobID, Status: model.JobQueued, CreatedAt: time.Now().UTC()}
	if err := WriteJob(dir, j); err != nil {
		t.Fatal(err)
	}
	got, err := ReadJob(dir, jobID)
	if err != nil || got.JobID != jobID {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestConfigHashSHA256(t *testing.T) {
	h := ConfigHashSHA256([]byte("a"))
	if len(h) != 64 {
		t.Fatal(h)
	}
}

func TestAppendOrchestratorLog(t *testing.T) {
	dir := t.TempDir()
	jobID := "j1"
	if err := InitJobDirs(dir, jobID); err != nil {
		t.Fatal(err)
	}
	if err := AppendOrchestratorLog(dir, jobID, "[INFO] line1"); err != nil {
		t.Fatal(err)
	}
	if err := AppendOrchestratorLog(dir, jobID, "[INFO] line2"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(OrchestratorLogPath(dir, jobID))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "line1") || !strings.Contains(s, "line2") {
		t.Fatal(s)
	}
}

func TestLatestJobID(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	if err := InitJobDirs(root, "older"); err != nil {
		t.Fatal(err)
	}
	if err := WriteJob(root, &model.Job{JobID: "older", Status: model.JobSucceeded, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(filepath.Join(JobRoot(root, "older"), "job.json"), oldTime, oldTime)

	if err := InitJobDirs(root, "newer"); err != nil {
		t.Fatal(err)
	}
	if err := WriteJob(root, &model.Job{JobID: "newer", Status: model.JobSucceeded, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	id, err := LatestJobID(root)
	if err != nil || id != "newer" {
		t.Fatalf("got %q %v", id, err)
	}
}
