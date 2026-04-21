package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/report"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/google/uuid"
)

type Action string

const (
	ActionConfirm Action = "confirm"
	ActionReject  Action = "reject"
	ActionReopen  Action = "reopen"
)

func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "confirm", "confirmed":
		return ActionConfirm, nil
	case "reject", "rejected", "false-positive", "fp":
		return ActionReject, nil
	case "reopen", "open":
		return ActionReopen, nil
	default:
		return "", fmt.Errorf("unknown review action %q (use confirm, reject, reopen)", s)
	}
}

func Apply(workDir, jobID, findingID string, act Action, note, actor string) error {
	if strings.TrimSpace(findingID) == "" {
		return fmt.Errorf("findingId required")
	}
	if actor == "" {
		actor = os.Getenv("USER")
		if actor == "" {
			actor = "operator"
		}
	}
	findings, err := storage.LoadFindingsJSON(workDir, jobID, "findings-final.json")
	if err != nil {
		return fmt.Errorf("load findings-final: %w", err)
	}
	idx := -1
	for i := range findings {
		if findings[i].FindingID == findingID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("finding %q not found in findings-final.json", findingID)
	}
	f := &findings[idx]
	prev := f.LifecycleStatus
	switch act {
	case ActionConfirm:
		f.LifecycleStatus = model.LifecycleConfirmed
		f.LastSeenAt = time.Now().UTC()
	case ActionReject:
		f.LifecycleStatus = model.LifecycleFalsePositiveSuppressed
		if strings.TrimSpace(f.SuppressionReason) == "" {
			if note != "" {
				f.SuppressionReason = note
			} else {
				f.SuppressionReason = "manual review: rejected / false positive"
			}
		}
	case ActionReopen:
		f.LifecycleStatus = model.LifecycleDetected
		f.SuppressionReason = ""
	default:
		return fmt.Errorf("internal: bad action %q", act)
	}
	now := time.Now().UTC()
	f.ReviewedBy = actor
	f.ReviewedAt = &now
	f.ReviewNote = strings.TrimSpace(note)

	evID := uuid.NewString()
	payload := model.ManualReviewPayload{
		Action:            string(act),
		Note:              f.ReviewNote,
		Actor:             actor,
		PreviousLifecycle: string(prev),
	}
	ev := model.Evidence{
		EvidenceID: evID,
		Type:       model.EvidenceManualReview,
		StepType:   model.StepManualReview,
		ContextID:  firstContextID(workDir, jobID),
		Payload:    payload,
	}
	f.EvidenceRefs = append(f.EvidenceRefs, evID)

	if err := storage.WriteEvidence(workDir, jobID, &ev); err != nil {
		return err
	}
	if err := storage.WriteFindingsJSON(workDir, jobID, "findings-final.json", findings); err != nil {
		return err
	}
	return regenerateReport(workDir, jobID, findings)
}

func firstContextID(workDir, jobID string) string {
	dir := filepath.Join(storage.JobRoot(workDir, jobID), "contexts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var snap struct {
			ContextID string `json:"contextId"`
		}
		if json.Unmarshal(data, &snap) == nil && snap.ContextID != "" {
			return snap.ContextID
		}
	}
	return ""
}

func regenerateReport(workDir, jobID string, findings []model.Finding) error {
	evidenceByID, err := storage.LoadEvidenceDir(workDir, jobID)
	if err != nil {
		return fmt.Errorf("load evidence: %w", err)
	}
	cfg, err := storage.LoadScanConfig(workDir, jobID)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	j, err := storage.ReadJob(workDir, jobID)
	if err != nil {
		return fmt.Errorf("load job: %w", err)
	}
	baseURL := ""
	if len(cfg.Targets) > 0 {
		baseURL = cfg.Targets[0].BaseURL
	}
	preset := cfg.Scan.Preset
	if preset == "" {
		preset = "custom"
	}
	started := j.CreatedAt
	finished := time.Now().UTC()
	if j.FinishedAt != nil {
		finished = *j.FinishedAt
	}
	updated := time.Now().UTC()
	md := report.RenderMarkdown(cfg.Job.Name, baseURL, preset, started, finished, findings, evidenceByID, cfg.ReportIncludeEvidence(), cfg.Budgets.Verification.EvidenceThreshold, &updated, nil)
	if err := storage.WriteReportMD(workDir, jobID, md); err != nil {
		return err
	}
	mdPath := filepath.Join(storage.JobRoot(workDir, jobID), "reports", "report.md")
	docxPath := filepath.Join(storage.JobRoot(workDir, jobID), "reports", "report.docx")
	ref := ""
	if cfg.Outputs.Docx != nil {
		ref = report.ResolveReferenceDoc(cfg.Outputs.Docx.TemplateRef, workDir)
	}
	_ = report.PandocToDocxOptional(mdPath, docxPath, ref)
	return nil
}
