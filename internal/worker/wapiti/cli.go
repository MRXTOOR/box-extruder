package wapiti

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/google/uuid"
)

type CLIOptions struct {
	Binary    string
	Target    string
	OutDir    string
	ScanForce string // low|medium|high or native (paranoid|sneaky|polite|normal|aggressive|insane)
	Timeout   int    // seconds
	// Headers are injected as global request headers (-H). Cookie uses -c JSON file (Wapiti 3.x).
	Headers map[string]string
	// InsecureSkipTLSVerify maps to --verify-ssl 0.
	InsecureSkipTLSVerify bool
	ContextID string
	Dedupe    config.DedupeConfig
}

type jsonReport struct {
	Vulnerabilities map[string][]jsonReportEntry `json:"vulnerabilities"`
}

type jsonReportEntry struct {
	Method    string          `json:"method"`
	Path      string          `json:"path"`
	Level     json.RawMessage `json:"level"`
	Info      string          `json:"info"`
	Module    string          `json:"module"`
	Parameter string          `json:"parameter"`
}

func ResolveBinary() string {
	if v := strings.TrimSpace(os.Getenv("DAST_WAPITI_BIN")); v != "" {
		return v
	}
	return "wapiti"
}

func RunCLI(opts CLIOptions) ([]model.Finding, []model.Evidence, error) {
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		return nil, nil, fmt.Errorf("wapiti: empty target")
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return nil, nil, err
	}
	bin := strings.TrimSpace(opts.Binary)
	if bin == "" {
		bin = ResolveBinary()
	}
	execPath, err := exec.LookPath(bin)
	if err != nil {
		return nil, nil, fmt.Errorf("wapiti: binary %q not found (%w); install wapiti or set DAST_WAPITI_BIN", bin, err)
	}
	reportPath := filepath.Join(opts.OutDir, "wapiti-report.json")
	args := []string{
		"-u", target,
		"-f", "json",
		"-o", reportPath,
		"--flush-session",
	}
	authArgs, err := buildAuthArgs(opts.Headers, opts.OutDir)
	if err != nil {
		return nil, nil, err
	}
	args = append(args, authArgs...)
	if sf := normalizeScanForce(opts.ScanForce); sf != "" {
		args = append(args, "-S", sf)
	}
	// Wapiti 3.x: -t is per-request timeout; --max-scan-time caps total scan duration.
	args = append(args, "-t", "30")
	maxScan := opts.Timeout
	if maxScan <= 0 {
		maxScan = 600
	}
	if maxScan < 60 {
		maxScan = 60
	}
	args = append(args, "--max-scan-time", fmt.Sprintf("%d", maxScan))
	if opts.InsecureSkipTLSVerify {
		args = append(args, "--verify-ssl", "0")
	}
	cmd := exec.Command(execPath, args...)
	out, runErr := cmd.CombinedOutput()
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		if runErr != nil {
			return nil, nil, fmt.Errorf("wapiti: %w: %s", runErr, truncate(string(out), 3000))
		}
		return nil, nil, fmt.Errorf("wapiti: report not written: %w", readErr)
	}
	f, e, perr := parseJSONReport(data, target, opts.ContextID, opts.Dedupe)
	if perr != nil {
		return nil, nil, perr
	}
	return f, e, nil
}

func parseJSONReport(data []byte, baseURL, ctxID string, dedupe config.DedupeConfig) ([]model.Finding, []model.Evidence, error) {
	var rep jsonReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, nil, fmt.Errorf("wapiti json: %w", err)
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0, 32)
	evidence := make([]model.Evidence, 0, 32)
	for vulnType, items := range rep.Vulnerabilities {
		vType := strings.TrimSpace(vulnType)
		if vType == "" {
			vType = "wapiti-vulnerability"
		}
		for _, it := range items {
			rawURL := strings.TrimSpace(it.Path)
			if rawURL == "" {
				continue
			}
			if strings.HasPrefix(rawURL, "/") {
				rawURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/") + rawURL
			}
			method := strings.ToUpper(strings.TrimSpace(it.Method))
			if method == "" {
				method = "GET"
			}
			locKey := noise.BuildLocationKeyFromHTTP(dedupe, method, rawURL)
			if p := strings.TrimSpace(it.Parameter); p != "" {
				locKey += "#param=" + p
			}
			evID := uuid.NewString()
			desc := strings.TrimSpace(it.Info)
			if m := strings.TrimSpace(it.Module); m != "" {
				if desc != "" {
					desc += "\n"
				}
				desc += "module: " + m
			}
			findings = append(findings, model.Finding{
				FindingID:       uuid.NewString(),
				RuleID:          "wapiti:" + strings.ToLower(strings.ReplaceAll(vType, " ", "-")),
				Category:        vType,
				Severity:        mapSeverity(parseLevel(it.Level)),
				Confidence:      0.8,
				LocationKey:     locKey,
				LifecycleStatus: model.LifecycleDetected,
				FirstSeenAt:     now,
				LastSeenAt:      now,
				EvidenceRefs:    []string{evID},
				Title:           "Wapiti: " + vType,
				Description:     desc,
			})
			evidence = append(evidence, model.Evidence{
				EvidenceID: evID,
				Type:       model.EvidenceHTTPRequestResponse,
				StepType:   model.StepWapiti,
				ContextID:  ctxID,
				Payload: model.HTTPRequestResponsePayload{
					Method: method,
					URL:    rawURL,
				},
			})
		}
	}
	return findings, evidence, nil
}

func mapSeverity(level string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "3", "high":
		return model.SeverityHigh
	case "2", "medium":
		return model.SeverityMedium
	case "1", "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func parseLevel(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return strings.Trim(string(raw), `"`)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func buildAuthArgs(headers map[string]string, outDir string) ([]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		if strings.TrimSpace(k) != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var args []string
	for _, k := range keys {
		v := strings.TrimSpace(headers[k])
		if v == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "cookie") {
			cookiePath := filepath.Join(outDir, "wapiti-cookies.json")
			if err := writeCookieFile(cookiePath, v); err != nil {
				return nil, fmt.Errorf("wapiti cookies: %w", err)
			}
			args = append(args, "-c", cookiePath)
			continue
		}
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	return args, nil
}

func writeCookieFile(path, raw string) error {
	type cookieEntry struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var entries []cookieEntry
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		entries = append(entries, cookieEntry{
			Name:  strings.TrimSpace(name),
			Value: strings.TrimSpace(value),
		})
	}
	if len(entries) == 0 {
		return fmt.Errorf("no cookies parsed")
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func normalizeScanForce(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return ""
	case "low":
		return "polite"
	case "medium":
		return "normal"
	case "high":
		return "aggressive"
	case "paranoid", "sneaky", "polite", "normal", "aggressive", "insane":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return ""
	}
}
