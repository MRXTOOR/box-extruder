package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

// JobRoot returns work/jobs/{jobId}.
func JobRoot(workDir, jobID string) string {
	return filepath.Join(workDir, "jobs", jobID)
}

func mkdirAll(p string) error {
	return os.MkdirAll(p, 0o755)
}

// InitJobDirs creates the standard directory tree.
func InitJobDirs(workDir, jobID string) error {
	root := JobRoot(workDir, jobID)
	dirs := []string{
		filepath.Join(root, "config"),
		filepath.Join(root, "contexts"),
		filepath.Join(root, "evidence"),
		filepath.Join(root, "findings"),
		filepath.Join(root, "reports"),
		filepath.Join(root, "events"),
		filepath.Join(root, "logs"),
		filepath.Join(root, "logs", "workers"),
	}
	for _, d := range dirs {
		if err := mkdirAll(d); err != nil {
			return err
		}
	}
	return nil
}

// WriteConfigSnapshot writes YAML bytes and config hash.
func WriteConfigSnapshot(workDir, jobID string, yamlBytes []byte, hash string) error {
	root := JobRoot(workDir, jobID)
	if err := mkdirAll(filepath.Join(root, "config")); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "config", "scan-as-code.yaml"), yamlBytes, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "config", "configHash.txt"), []byte(hash+"\n"), 0o644)
}

// ConfigHashSHA256 returns hex sha256 of bytes.
func ConfigHashSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// WriteJob writes job.json.
func WriteJob(workDir string, j *model.Job) error {
	root := JobRoot(workDir, j.JobID)
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "job.json"), append(data, '\n'), 0o644)
}

// ReadJob reads job.json.
func ReadJob(workDir, jobID string) (*model.Job, error) {
	p := filepath.Join(JobRoot(workDir, jobID), "job.json")
	data, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ReadJob: failed to read %s: %v\n", p, err)
		return nil, err
	}
	var j model.Job
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// AppendEvent appends one JSON line to events.jsonl.
func AppendEvent(workDir, jobID string, ev map[string]any) error {
	root := JobRoot(workDir, jobID)
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root, "events", "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

// AppendOrchestratorLog appends a line to logs/orchestrator.log with RFC3339 timestamp prefix.
func AppendOrchestratorLog(workDir, jobID, msg string) error {
	root := JobRoot(workDir, jobID)
	if err := mkdirAll(filepath.Join(root, "logs")); err != nil {
		return err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	line := ts + " " + msg + "\n"
	f, err := os.OpenFile(filepath.Join(root, "logs", "orchestrator.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// OrchestratorLogPath returns path to orchestrator.log for a job.
func OrchestratorLogPath(workDir, jobID string) string {
	return filepath.Join(JobRoot(workDir, jobID), "logs", "orchestrator.log")
}

// WriteContext writes context-{id}.json.
func WriteContext(workDir, jobID string, ctx *model.ContextSnapshot) error {
	root := JobRoot(workDir, jobID)
	data, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("context-%s.json", ctx.ContextID)
	return os.WriteFile(filepath.Join(root, "contexts", name), append(data, '\n'), 0o644)
}

// WriteEvidence writes evidence-{id}.json.
func WriteEvidence(workDir, jobID string, ev *model.Evidence) error {
	root := JobRoot(workDir, jobID)
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("evidence-%s.json", ev.EvidenceID)
	return os.WriteFile(filepath.Join(root, "evidence", name), append(data, '\n'), 0o644)
}

// WriteFindingsJSON writes findings-raw.json or findings-final.json.
func WriteFindingsJSON(workDir, jobID, filename string, findings []model.Finding) error {
	root := JobRoot(workDir, jobID)
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "findings", filename), append(data, '\n'), 0o644)
}

// LoadFindingsJSON reads findings JSON from findings/{filename}.
func LoadFindingsJSON(workDir, jobID, filename string) ([]model.Finding, error) {
	p := filepath.Join(JobRoot(workDir, jobID), "findings", filename)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out []model.Finding
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// evidenceFileJSON — payload как RawMessage, чтобы при загрузке не терять структуру.
type evidenceFileJSON struct {
	EvidenceID string          `json:"evidenceId"`
	Type       string          `json:"type"`
	StepType   string          `json:"stepType"`
	ContextID  string          `json:"contextId"`
	Payload    json.RawMessage `json:"payload"`
}

// LoadEvidenceDir загружает все evidence-*.json в map по evidenceId.
func LoadEvidenceDir(workDir, jobID string) (map[string]model.Evidence, error) {
	dir := filepath.Join(JobRoot(workDir, jobID), "evidence")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.Evidence)
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "evidence-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var raw evidenceFileJSON
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		var payload any
		if len(raw.Payload) > 0 && string(raw.Payload) != "null" {
			if err := json.Unmarshal(raw.Payload, &payload); err != nil {
				return nil, fmt.Errorf("%s payload: %w", e.Name(), err)
			}
		}
		ev := model.Evidence{
			EvidenceID: raw.EvidenceID,
			Type:       model.EvidenceType(raw.Type),
			StepType:   model.StepType(raw.StepType),
			ContextID:  raw.ContextID,
			Payload:    payload,
		}
		out[ev.EvidenceID] = ev
	}
	return out, nil
}

// WriteReportMD writes reports/report.md.
func WriteReportMD(workDir, jobID string, md []byte) error {
	root := JobRoot(workDir, jobID)
	return os.WriteFile(filepath.Join(root, "reports", "report.md"), md, 0o644)
}

// ScanConfigPath returns path to saved config.
func ScanConfigPath(workDir, jobID string) string {
	return filepath.Join(JobRoot(workDir, jobID), "config", "scan-as-code.yaml")
}

// LoadScanConfig reads saved YAML config into struct.
func LoadScanConfig(workDir, jobID string) (*config.ScanAsCode, error) {
	p := ScanConfigPath(workDir, jobID)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return config.ParseScanAsCode(data)
}

// LatestJobID returns the job id of the most recently modified directory under work/jobs.
func LatestJobID(workDir string) (string, error) {
	jobsDir := filepath.Join(workDir, "jobs")
	entries, err := os.ReadDir(jobsDir)
	if err != nil {
		return "", err
	}
	var bestID string
	var bestMod int64 = -1
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		st, err := os.Stat(filepath.Join(jobsDir, id, "job.json"))
		if err != nil {
			continue
		}
		mt := st.ModTime().UnixNano()
		if mt > bestMod {
			bestMod = mt
			bestID = id
		}
	}
	if bestID == "" {
		return "", fmt.Errorf("no jobs under %s", jobsDir)
	}
	return bestID, nil
}

// JobSummary contains minimal info for job listing.
type JobSummary struct {
	JobID      string     `json:"jobId"`
	Name       string     `json:"name,omitempty"`
	TargetURL  string     `json:"targetUrl,omitempty"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"createdAt"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

// ListJobs returns all jobs sorted by createdAt descending.
func ListJobs(workDir string) ([]JobSummary, error) {
	jobsDir := filepath.Join(workDir, "jobs")
	entries, err := os.ReadDir(jobsDir)
	if err != nil {
		return nil, err
	}
	var jobs []JobSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		j, err := ReadJob(workDir, id)
		if err != nil {
			continue
		}
		summary := JobSummary{
			JobID:      j.JobID,
			Status:     string(j.Status),
			CreatedAt:  j.CreatedAt,
			StartedAt:  j.StartedAt,
			FinishedAt: j.FinishedAt,
		}
		cfg, err := LoadScanConfig(workDir, id)
		if err == nil {
			if cfg.Job.Name != "" {
				summary.Name = cfg.Job.Name
			}
			if len(cfg.Targets) > 0 {
				summary.TargetURL = cfg.Targets[0].BaseURL
			}
		}
		jobs = append(jobs, summary)
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
	})
	return jobs, nil
}

// DeleteJob removes the entire job directory.
func DeleteJob(workDir, jobID string) error {
	root := JobRoot(workDir, jobID)
	return os.RemoveAll(root)
}
