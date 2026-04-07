package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/storage"
)

func TestApplyConfirmWritesEvidenceAndReport(t *testing.T) {
	dir := t.TempDir()
	jobID := "job-review-test"
	yamlBytes, err := os.ReadFile(filepath.Join("..", "runner", "testdata", "minimal-scan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.InitJobDirs(dir, jobID); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteConfigSnapshot(dir, jobID, yamlBytes, storage.ConfigHashSHA256(yamlBytes)); err != nil {
		t.Fatal(err)
	}
	j := &model.Job{
		JobID:      jobID,
		CreatedAt:  time.Now().UTC(),
		Status:     model.JobSucceeded,
		ConfigHash: "x",
	}
	if err := storage.WriteJob(dir, j); err != nil {
		t.Fatal(err)
	}
	fid := "finding-1"
	now := time.Now().UTC()
	findings := []model.Finding{{
		FindingID:       fid,
		RuleID:          "rule-x",
		Category:        "test",
		Severity:        model.SeverityHigh,
		Confidence:      0.5,
		LocationKey:     "GET /a",
		LifecycleStatus: model.LifecycleUnconfirmed,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		Title:           "Test finding",
	}}
	if err := storage.WriteFindingsJSON(dir, jobID, "findings-final.json", findings); err != nil {
		t.Fatal(err)
	}
	if err := Apply(dir, jobID, fid, ActionConfirm, "verified manually", "alice"); err != nil {
		t.Fatal(err)
	}
	after, err := storage.LoadFindingsJSON(dir, jobID, "findings-final.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].LifecycleStatus != model.LifecycleConfirmed {
		t.Fatalf("lifecycle: %+v", after[0].LifecycleStatus)
	}
	if after[0].ReviewedBy != "alice" || after[0].ReviewNote != "verified manually" {
		t.Fatalf("review fields: %+v", after[0])
	}
	if len(after[0].EvidenceRefs) != 1 {
		t.Fatalf("evidence refs: %v", after[0].EvidenceRefs)
	}
	ev, err := storage.LoadEvidenceDir(dir, jobID)
	if err != nil {
		t.Fatal(err)
	}
	eid := after[0].EvidenceRefs[0]
	e := ev[eid]
	if e.Type != model.EvidenceManualReview {
		t.Fatalf("evidence type %s", e.Type)
	}
	reportPath := filepath.Join(storage.JobRoot(dir, jobID), "reports", "report.md")
	md, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "Audit trail (manual review)") {
		t.Fatalf("report missing audit section:\n%s", md)
	}
	if !strings.Contains(string(md), "alice") {
		t.Fatal("report missing reviewer")
	}
}

func TestApplyReject(t *testing.T) {
	dir := t.TempDir()
	jobID := "job-reject"
	yamlBytes, err := os.ReadFile(filepath.Join("..", "runner", "testdata", "minimal-scan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_ = storage.InitJobDirs(dir, jobID)
	_ = storage.WriteConfigSnapshot(dir, jobID, yamlBytes, storage.ConfigHashSHA256(yamlBytes))
	_ = storage.WriteJob(dir, &model.Job{JobID: jobID, CreatedAt: time.Now().UTC(), Status: model.JobSucceeded, ConfigHash: "x"})
	fid := "f2"
	now := time.Now().UTC()
	_ = storage.WriteFindingsJSON(dir, jobID, "findings-final.json", []model.Finding{{
		FindingID: fid, RuleID: "r", Category: "c", Severity: model.SeverityLow, Confidence: 1,
		LocationKey: "x", LifecycleStatus: model.LifecycleDetected, FirstSeenAt: now, LastSeenAt: now,
	}})
	if err := Apply(dir, jobID, fid, ActionReject, "", "bob"); err != nil {
		t.Fatal(err)
	}
	after, _ := storage.LoadFindingsJSON(dir, jobID, "findings-final.json")
	if after[0].LifecycleStatus != model.LifecycleFalsePositiveSuppressed {
		t.Fatal(after[0].LifecycleStatus)
	}
	if after[0].SuppressionReason == "" {
		t.Fatal("expected suppression reason")
	}
}
