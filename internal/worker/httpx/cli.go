package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/google/uuid"
)

const probeRuleID = "httpx:probe"

type CLIOptions struct {
	Binary    string
	Targets   []string
	Headers   []string
	OutDir    string
	Timeout   time.Duration
	ContextID string
	Dedupe    config.DedupeConfig
}

type jsonLine struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Title       string   `json:"title"`
	Technologies []string `json:"tech"`
	Failed      bool     `json:"failed"`
}

func ResolveBinary() string {
	if v := strings.TrimSpace(os.Getenv("DAST_HTTPX_BIN")); v != "" {
		return v
	}
	return "httpx"
}

func InputCap() int {
	if v := strings.TrimSpace(os.Getenv("DAST_HTTPX_INPUT_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 3000
}

func Drop4xxEnabled() bool {
	return strings.TrimSpace(os.Getenv("DAST_HTTPX_DROP_4XX")) == "1"
}

// FilterFeedURLs returns cleaned Katana feed URLs capped for httpx input.
func FilterFeedURLs(feed []string) []string {
	capN := InputCap()
	seen := make(map[string]struct{})
	var out []string
	for _, u := range feed {
		u = strings.TrimSpace(u)
		if u == "" || noise.IsGarbageDiscoveryURL(u) {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
		if len(out) >= capN {
			break
		}
	}
	return out
}

func RunCLI(opts CLIOptions) (findings []model.Finding, evidence []model.Evidence, aliveURLs, deadURLs []string, err error) {
	if len(opts.Targets) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("httpx: no targets")
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return nil, nil, nil, nil, err
	}
	listPath := filepath.Join(opts.OutDir, "httpx-targets.txt")
	var b strings.Builder
	for _, t := range opts.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		b.WriteString(t)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return nil, nil, nil, nil, fmt.Errorf("httpx: empty target list")
	}
	if err := os.WriteFile(listPath, []byte(b.String()), 0o644); err != nil {
		return nil, nil, nil, nil, err
	}

	bin := strings.TrimSpace(opts.Binary)
	if bin == "" {
		bin = ResolveBinary()
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("httpx: binary %q not found (%w); set DAST_HTTPX_BIN", bin, err)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-l", listPath,
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-follow-redirects",
		"-silent",
	}
	for _, h := range opts.Headers {
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", h)
		}
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	resultsPath := filepath.Join(opts.OutDir, "httpx-results.jsonl")
	_ = os.WriteFile(resultsPath, stdout.Bytes(), 0o644)

	lines := parseJSONL(stdout.Bytes())
	drop4xx := Drop4xxEnabled()
	now := time.Now().UTC()
	for _, row := range lines {
		if row.URL == "" || row.Failed {
			continue
		}
		if row.StatusCode == 404 || row.StatusCode == 410 {
			deadURLs = append(deadURLs, row.URL)
			if drop4xx {
				continue
			}
		}
		aliveURLs = append(aliveURLs, row.URL)
		locKey := noise.BuildLocationKeyFromHTTP(opts.Dedupe, "GET", row.URL)
		evID := uuid.NewString()
		desc := fmt.Sprintf("status=%d", row.StatusCode)
		if t := strings.TrimSpace(row.Title); t != "" {
			desc += "; title=" + t
		}
		if len(row.Technologies) > 0 {
			desc += "; tech=" + strings.Join(row.Technologies, ", ")
		}
		findings = append(findings, model.Finding{
			FindingID:       uuid.NewString(),
			RuleID:          probeRuleID,
			Category:        "recon",
			Severity:        model.SeverityInfo,
			Confidence:      1,
			LocationKey:     locKey,
			LifecycleStatus: model.LifecycleDetected,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			EvidenceRefs:    []string{evID},
			Title:           "httpx probe",
			Description:     desc,
		})
		evidence = append(evidence, model.Evidence{
			EvidenceID: evID,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepHttpx,
			ContextID:  opts.ContextID,
			Payload: model.HTTPRequestResponsePayload{
				Method:     "GET",
				URL:        row.URL,
				StatusCode: row.StatusCode,
			},
		})
	}
	if len(findings) == 0 && runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, nil, nil, nil, fmt.Errorf("httpx: %s", msg)
	}
	return findings, evidence, aliveURLs, deadURLs, nil
}

func parseJSONL(data []byte) []jsonLine {
	var out []jsonLine
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row jsonLine
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		out = append(out, row)
	}
	return out
}
