package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/google/uuid"
)

// CLIOptions runs ProjectDiscovery nuclei against targets and template paths (-t).
type CLIOptions struct {
	Binary        string
	Targets       []string
	ListFile      string
	TemplatePaths []string
	Headers   []string
	ExtraArgs []string
	RateLimit int
	Timeout   time.Duration
	ContextID string
	Dedupe    config.DedupeConfig
}

// ResolveNucleiBinary returns DAST_NUCLEI_BIN or "nuclei".
func ResolveNucleiBinary() string {
	if v := strings.TrimSpace(os.Getenv("DAST_NUCLEI_BIN")); v != "" {
		return v
	}
	return "nuclei"
}

// RunCLI executes nuclei -jsonl and maps each JSON line to Finding + Evidence.
func RunCLI(opts CLIOptions) ([]model.Finding, []model.Evidence, error) {
	listFile := strings.TrimSpace(opts.ListFile)
	hasList := listFile != ""
	hasTargets := len(opts.Targets) > 0
	if hasList == hasTargets {
		return nil, nil, fmt.Errorf("nuclei CLI: set exactly one of Targets or ListFile")
	}
	if hasList {
		if _, err := os.Stat(listFile); err != nil {
			return nil, nil, fmt.Errorf("nuclei CLI list file: %w", err)
		}
	}
	if len(opts.TemplatePaths) == 0 {
		return nil, nil, fmt.Errorf("nuclei CLI: no template paths")
	}
	bin := strings.TrimSpace(opts.Binary)
	if bin == "" {
		bin = ResolveNucleiBinary()
	}
	execPath, err := exec.LookPath(bin)
	if err != nil {
		return nil, nil, fmt.Errorf("nuclei CLI: binary %q not found (%w); install nuclei or set DAST_NUCLEI_BIN", bin, err)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{"-silent", "-nc", "-jsonl", "-ot"}
	if hasList {
		args = append(args, "-l", listFile)
	} else {
		for _, u := range opts.Targets {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			args = append(args, "-u", u)
		}
	}
	for _, tp := range opts.TemplatePaths {
		tp = strings.TrimSpace(tp)
		if tp == "" {
			continue
		}
		args = append(args, "-t", tp)
	}
	for _, h := range opts.Headers {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		args = append(args, "-H", h)
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", opts.RateLimit))
	}
	args = append(args, opts.ExtraArgs...)

	cmd := exec.CommandContext(ctx, execPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	out := stdout.Bytes()
	if runErr != nil && len(bytes.TrimSpace(out)) == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, nil, fmt.Errorf("nuclei CLI: %w: %s", runErr, truncateRunMsg(msg, 4000))
	}
	findings, evidence, perr := parseNucleiJSONL(out, opts.ContextID, opts.Dedupe)
	if perr != nil {
		return nil, nil, perr
	}
	return findings, evidence, nil
}

func truncateRunMsg(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// nucleiJSONLine is a tolerant subset of nuclei -jsonl fields (versions differ).
type nucleiJSONLine struct {
	TemplateID   string `json:"template-id"`
	TemplatePath string `json:"template-path"`
	Host         string `json:"host"`
	MatchedAt    string `json:"matched-at"`
	Type         string `json:"type"`
	MatcherName  string `json:"matcher-name"`
	Request      string `json:"request"`
	Response     string `json:"response"`
	CurlCommand  string `json:"curl-command"`
	Info         struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	} `json:"info"`
}

func parseNucleiJSONL(raw []byte, ctxID string, dedupe config.DedupeConfig) ([]model.Finding, []model.Evidence, error) {
	var findings []model.Finding
	var evidence []model.Evidence
	now := time.Now().UTC()
	sc := bufio.NewScanner(bytes.NewReader(raw))
	// Lines can be large (raw request/response).
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var row nucleiJSONLine
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, nil, fmt.Errorf("nuclei JSONL line %d: %w", lineNo, err)
		}
		f, ev := nucleiRowToModels(row, ctxID, dedupe, now)
		if f == nil {
			continue
		}
		findings = append(findings, *f)
		evidence = append(evidence, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return findings, evidence, nil
}

func nucleiRowToModels(row nucleiJSONLine, ctxID string, dedupe config.DedupeConfig, now time.Time) (*model.Finding, model.Evidence) {
	tplID := strings.TrimSpace(row.TemplateID)
	if tplID == "" && row.TemplatePath != "" {
		tplID = strings.TrimSuffix(filepath.Base(row.TemplatePath), filepath.Ext(row.TemplatePath))
	}
	if tplID == "" {
		tplID = "unknown"
	}
	matched := strings.TrimSpace(row.MatchedAt)
	if matched == "" {
		matched = strings.TrimSpace(row.Host)
	}
	if matched == "" {
		return nil, model.Evidence{}
	}
	method, _ := firstLineMethodURL(row.Request)
	if method == "" {
		method = "GET"
	}
	locKey := noise.BuildLocationKeyFromHTTP(dedupe, method, matched)
	sev := parseSeverity(row.Info.Severity)
	title := first(row.Info.Name, tplID)
	desc := strings.TrimSpace(row.Info.Description)
	if row.MatcherName != "" {
		if desc != "" {
			desc += "\n"
		}
		desc += "matcher: " + row.MatcherName
	}
	if row.CurlCommand != "" && len(row.CurlCommand) < 500 {
		if desc != "" {
			desc += "\n"
		}
		desc += row.CurlCommand
	}
	evID := uuid.NewString()
	f := model.Finding{
		FindingID:       uuid.NewString(),
		RuleID:          "nuclei-cli:" + tplID,
		Category:        "nuclei-template",
		Severity:        sev,
		Confidence:      0.9,
		LocationKey:     locKey,
		LifecycleStatus: model.LifecycleDetected,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		EvidenceRefs:    []string{evID},
		Title:           title,
		Description:     desc,
	}
	ev := model.Evidence{
		EvidenceID: evID,
		Type:       model.EvidenceHTTPRequestResponse,
		StepType:   model.StepNucleiCLI,
		ContextID:  ctxID,
		Payload: model.HTTPRequestResponsePayload{
			Method:              method,
			URL:                 matched,
			StatusCode:          statusFromHTTPResponse(row.Response),
			ResponseBodySnippet: truncate(strings.TrimSpace(row.Response), 1500),
		},
	}
	return &f, ev
}

func firstLineMethodURL(raw string) (method, url string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	line := raw
	if i := strings.Index(raw, "\n"); i >= 0 {
		line = raw[:i]
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", ""
	}
	method = strings.ToUpper(parts[0])
	url = parts[1]
	return method, url
}

func statusFromHTTPResponse(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	line := raw
	if i := strings.Index(raw, "\n"); i >= 0 {
		line = raw[:i]
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	var code int
	for _, p := range parts[1:] {
		if _, err := fmt.Sscanf(p, "%d", &code); err == nil && code >= 100 && code < 600 {
			return code
		}
	}
	return 0
}
