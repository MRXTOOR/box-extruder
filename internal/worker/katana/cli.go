package katana

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/google/uuid"
)

// CLIOptions runs ProjectDiscovery katana against seed URLs.
type CLIOptions struct {
	Binary        string
	Targets       []string
	Headers       []string // "Name: value" для -H
	Depth         int      // -d, 0 = не передавать (дефолт katana)
	Concurrency   int      // -c
	TimeoutSecs   int      // -timeout на запрос
	RateLimit     int      // -rl
	CrawlDuration string   // -ct, например "60s"
	CrawlScope    []string // -cs regex
	CrawlOutScope []string // -cos regex
	Headless      bool
	ExtraArgs     []string
	Timeout       time.Duration // общий таймаут процесса
	ContextID     string
	Dedupe        config.DedupeConfig
}

// ResolveKatanaBinary возвращает DAST_KATANA_BIN или "katana".
func ResolveKatanaBinary() string {
	if v := strings.TrimSpace(os.Getenv("DAST_KATANA_BIN")); v != "" {
		return v
	}
	return "katana"
}

// DockerKatanaImage возвращает DAST_KATANA_DOCKER_IMAGE (если задан — katana запускается через docker run).
func DockerKatanaImage() string {
	return strings.TrimSpace(os.Getenv("DAST_KATANA_DOCKER_IMAGE"))
}

// RunCLI запускает katana -jsonl и преобразует строки в Finding + Evidence.
func RunCLI(opts CLIOptions) ([]model.Finding, []model.Evidence, error) {
	if len(opts.Targets) == 0 {
		return nil, nil, fmt.Errorf("katana CLI: no targets")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{"-silent", "-nc", "-jsonl", "-or", "-ob"}
	for _, u := range opts.Targets {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		args = append(args, "-u", u)
	}
	for _, h := range opts.Headers {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		args = append(args, "-H", h)
	}
	if opts.Depth > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", opts.Depth))
	}
	if opts.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", opts.Concurrency))
	}
	if opts.TimeoutSecs > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", opts.TimeoutSecs))
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", opts.RateLimit))
	}
	if d := strings.TrimSpace(opts.CrawlDuration); d != "" {
		args = append(args, "-ct", d)
	}
	for _, re := range opts.CrawlScope {
		re = strings.TrimSpace(re)
		if re == "" {
			continue
		}
		args = append(args, "-cs", re)
	}
	for _, re := range opts.CrawlOutScope {
		re = strings.TrimSpace(re)
		if re == "" {
			continue
		}
		args = append(args, "-cos", re)
	}
	if opts.Headless {
		args = append(args, "-headless")
	}
	args = append(args, opts.ExtraArgs...)

	var cmd *exec.Cmd
	if img := DockerKatanaImage(); img != "" {
		dockerPath, derr := exec.LookPath("docker")
		if derr != nil {
			return nil, nil, fmt.Errorf("katana CLI: DAST_KATANA_DOCKER_IMAGE=%q задан, но docker не найден: %w", img, derr)
		}
		dockerArgs := []string{"run", "--rm"}
		if extra := strings.Fields(os.Getenv("DAST_KATANA_DOCKER_EXTRA")); len(extra) > 0 {
			dockerArgs = append(dockerArgs, extra...)
		}
		dockerArgs = append(dockerArgs, img)
		dockerArgs = append(dockerArgs, args...)
		cmd = exec.CommandContext(ctx, dockerPath, dockerArgs...)
	} else {
		bin := strings.TrimSpace(opts.Binary)
		if bin == "" {
			bin = ResolveKatanaBinary()
		}
		execPath, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("katana CLI: binary %q not found (%w); install katana, set DAST_KATANA_BIN, or DAST_KATANA_DOCKER_IMAGE (e.g. projectdiscovery/katana:latest)", bin, err)
		}
		cmd = exec.CommandContext(ctx, execPath, args...)
	}
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
		return nil, nil, fmt.Errorf("katana CLI: %w: %s", runErr, truncateRunMsg(msg, 4000))
	}
	findings, evidence, perr := parseKatanaJSONL(out, opts.ContextID, opts.Dedupe)
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

type katanaJSONLine struct {
	Request struct {
		Method    string `json:"method"`
		Endpoint  string `json:"endpoint"`
		Tag       string `json:"tag"`
		Attribute string `json:"attribute"`
		Source    string `json:"source"`
	} `json:"request"`
	Response struct {
		StatusCode int `json:"status_code"`
	} `json:"response"`
}

func parseKatanaJSONL(raw []byte, ctxID string, dedupe config.DedupeConfig) ([]model.Finding, []model.Evidence, error) {
	var findings []model.Finding
	var evidence []model.Evidence
	now := time.Now().UTC()
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var row katanaJSONLine
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, nil, fmt.Errorf("katana JSONL line %d: %w", lineNo, err)
		}
		f, ev := rowToModels(row, ctxID, dedupe, now)
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

func rowToModels(row katanaJSONLine, ctxID string, dedupe config.DedupeConfig, now time.Time) (*model.Finding, model.Evidence) {
	endpoint := strings.TrimSpace(row.Request.Endpoint)
	if endpoint == "" {
		return nil, model.Evidence{}
	}
	method := strings.ToUpper(strings.TrimSpace(row.Request.Method))
	if method == "" {
		method = "GET"
	}
	locKey := noise.BuildLocationKeyFromHTTP(dedupe, method, endpoint)
	desc := strings.TrimSpace(row.Request.Source)
	if row.Request.Tag != "" {
		if desc != "" {
			desc += "\n"
		}
		desc += fmt.Sprintf("extract: <%s %s>", row.Request.Tag, row.Request.Attribute)
	}
	evID := uuid.NewString()
	f := model.Finding{
		FindingID:       uuid.NewString(),
		RuleID:          "katana:discovered-url",
		Category:        "crawl-discovery",
		Severity:        model.SeverityInfo,
		Confidence:      0.75,
		LocationKey:     locKey,
		LifecycleStatus: model.LifecycleDetected,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		EvidenceRefs:    []string{evID},
		Title:           "Katana: обнаружен URL",
		Description:     desc,
	}
	ev := model.Evidence{
		EvidenceID: evID,
		Type:       model.EvidenceHTTPRequestResponse,
		StepType:   model.StepKatana,
		ContextID:  ctxID,
		Payload: model.HTTPRequestResponsePayload{
			Method:     method,
			URL:        endpoint,
			StatusCode: row.Response.StatusCode,
		},
	}
	return &f, ev
}
