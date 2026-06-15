package storage

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const DefaultDumpMaxBytes = 50 << 20 // 50 MiB

var secretYAMLRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)\s*:\s*\S+`)

// ScanSummary is included in dump archives and log API.
type ScanSummary struct {
	JobID          string   `json:"jobId"`
	Status         string   `json:"status"`
	TargetURL      string   `json:"targetUrl"`
	Source         string   `json:"source,omitempty"`
	StartedAt      string   `json:"startedAt,omitempty"`
	FinishedAt     string   `json:"finishedAt,omitempty"`
	FindingsCount  int      `json:"findingsCount"`
	Errors         []string `json:"errors"`
}

// ScanEvent is one parsed line from events.jsonl.
type ScanEvent struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Step    string `json:"step,omitempty"`
	Message string `json:"message"`
}

// WorkerLogFile describes a worker log file on disk.
type WorkerLogFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// ScanLogsResponse is returned by GET /scans/{id}/logs.
type ScanLogsResponse struct {
	Events          []ScanEvent     `json:"events"`
	OrchestratorTail []string       `json:"orchestratorTail"`
	WorkerFiles     []WorkerLogFile `json:"workerFiles"`
	Summary         *ScanSummary    `json:"summary,omitempty"`
}

// BuildScanDump writes a ZIP of job artifacts to w, enforcing maxBytes total.
func BuildScanDump(workDir, jobID string, w io.Writer, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = DefaultDumpMaxBytes
	}
	root := JobRoot(workDir, jobID)
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return fmt.Errorf("job directory not found")
	}

	zw := zip.NewWriter(w)
	defer zw.Close()

	var written int64
	addFile := func(zipName, diskPath string, transform func([]byte) []byte) error {
		info, err := os.Stat(diskPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		if written+info.Size() > maxBytes {
			return fmt.Errorf("dump size limit exceeded")
		}
		data, err := os.ReadFile(diskPath)
		if err != nil {
			return err
		}
		if transform != nil {
			data = transform(data)
		}
		fh := &zip.FileHeader{Name: zipName, Method: zip.Deflate}
		fh.SetModTime(info.ModTime())
		entry, err := zw.CreateHeader(fh)
		if err != nil {
			return err
		}
		n, err := entry.Write(data)
		written += int64(n)
		return err
	}

	entries := []struct {
		zipPath  string
		diskPath string
		transform func([]byte) []byte
	}{
		{"events/events.jsonl", filepath.Join(root, "events", "events.jsonl"), nil},
		{"logs/orchestrator.log", OrchestratorLogPath(workDir, jobID), nil},
		{"config/scan-as-code.yaml", ScanConfigPath(workDir, jobID), redactYAMLSecrets},
	}

	for _, e := range entries {
		if err := addFile(e.zipPath, e.diskPath, e.transform); err != nil {
			return err
		}
	}

	workersDir := filepath.Join(root, "logs", "workers")
	_ = filepath.Walk(workersDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		return addFile(rel, path, nil)
	})

	summaryBytes, _ := json.MarshalIndent(buildSummaryFromDisk(workDir, jobID, "", "", 0), "", "  ")
	if len(summaryBytes) > 0 {
		fh := &zip.FileHeader{Name: "summary.json", Method: zip.Deflate}
		fh.SetModTime(time.Now().UTC())
		entry, _ := zw.CreateHeader(fh)
		_, _ = entry.Write(summaryBytes)
	}

	ciMeta := filepath.Join(root, "ci", "jenkins.json")
	_ = addFile("ci/jenkins.json", ciMeta, nil)

	return nil
}

func redactYAMLSecrets(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if secretYAMLRe.MatchString(line) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				lines[i] = parts[0] + ": \"[СКРЫТО]\""
			}
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func ParseEventsFile(path string, levelFilter map[string]bool) ([]ScanEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []ScanEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		ev := ScanEvent{
			Time:    fmt.Sprint(raw["ts"], raw["time"], raw["timestamp"]),
			Level:   strings.ToLower(fmt.Sprint(raw["level"], raw["severity"])),
			Step:    fmt.Sprint(raw["step"], raw["stepType"], raw["phase"]),
			Message: fmt.Sprint(raw["msg"], raw["message"]),
		}
		if ev.Time == "" {
			ev.Time = time.Now().UTC().Format(time.RFC3339)
		}
		if levelFilter != nil && len(levelFilter) > 0 && !levelFilter[ev.Level] {
			continue
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

func TailFileLines(path string, n int) ([]string, error) {
	if n <= 0 {
		n = 200
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines, sc.Err()
}

func ListWorkerLogs(workDir, jobID string) ([]WorkerLogFile, error) {
	dir := filepath.Join(JobRoot(workDir, jobID), "logs", "workers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []WorkerLogFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		out = append(out, WorkerLogFile{Name: e.Name(), Size: size})
	}
	return out, nil
}

func buildSummaryFromDisk(workDir, jobID, status, targetURL string, findingsCount int) ScanSummary {
	sum := ScanSummary{
		JobID:         jobID,
		Status:        status,
		TargetURL:     targetURL,
		FindingsCount: findingsCount,
	}
	if j, err := ReadJob(workDir, jobID); err == nil && j != nil {
		if j.StartedAt != nil {
			sum.StartedAt = j.StartedAt.Format(time.RFC3339)
		}
		if j.FinishedAt != nil {
			sum.FinishedAt = j.FinishedAt.Format(time.RFC3339)
		}
		if sum.Status == "" {
			sum.Status = string(j.Status)
		}
	}
	eventsPath := filepath.Join(JobRoot(workDir, jobID), "events", "events.jsonl")
	if events, err := ParseEventsFile(eventsPath, nil); err == nil {
		for _, ev := range events {
			if ev.Level == "error" || ev.Level == "warn" || ev.Level == "warning" {
				sum.Errors = append(sum.Errors, ev.Message)
			}
		}
	}
	return sum
}

// ScanLogsParams configures LoadScanLogs.
type ScanLogsParams struct {
	WorkDir       string
	JobID         string
	Status        string
	TargetURL     string
	FindingsCount int
	LevelParam    string
	Tail          int
}

func LoadScanLogs(p ScanLogsParams) (*ScanLogsResponse, error) {
	levelFilter := parseLevelFilter(p.LevelParam)
	eventsPath := filepath.Join(JobRoot(p.WorkDir, p.JobID), "events", "events.jsonl")
	events, err := ParseEventsFile(eventsPath, levelFilter)
	if err != nil {
		return nil, err
	}
	tailLines, err := TailFileLines(OrchestratorLogPath(p.WorkDir, p.JobID), p.Tail)
	if err != nil {
		return nil, err
	}
	workers, err := ListWorkerLogs(p.WorkDir, p.JobID)
	if err != nil {
		return nil, err
	}
	sum := buildSummaryFromDisk(p.WorkDir, p.JobID, p.Status, p.TargetURL, p.FindingsCount)
	return &ScanLogsResponse{
		Events:           events,
		OrchestratorTail: tailLines,
		WorkerFiles:      workers,
		Summary:          &sum,
	}, nil
}

func parseLevelFilter(levelParam string) map[string]bool {
	if levelParam == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, p := range strings.Split(levelParam, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			m[p] = true
		}
	}
	return m
}

// WriteJSONFile writes v as indented JSON, creating parent directories.
func WriteJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
