package runner

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/box-extruder/dast/internal/payloads"
	"github.com/box-extruder/dast/internal/worker/katana"
	"github.com/google/uuid"
)

// demoBase is the reserved, non-routable domain (RFC 6761) used for the synthetic
// findings produced by dummyBundle. It is sample data, never a real target.
const demoBase = "https://example.invalid"

func dummyBundle(ctxID string) ([]model.Finding, []model.Evidence) {
	now := time.Now().UTC()
	evConfirmed := uuid.NewString()
	evUnconf := uuid.NewString()
	evSupp := uuid.NewString()
	loc := "GET " + demoBase + "/search?q=test"
	findings := []model.Finding{
		{
			FindingID:       uuid.NewString(),
			RuleID:          "demo-xss-001",
			Category:        "XSS",
			Severity:        model.SeverityHigh,
			Confidence:      0.9,
			LocationKey:     loc,
			LifecycleStatus: model.LifecycleConfirmed,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			EvidenceRefs:    []string{evConfirmed},
			Title:           "Demo reflected XSS (confirmed)",
		},
		{
			FindingID:       uuid.NewString(),
			RuleID:          "demo-sqli-weak",
			Category:        "SQL Injection",
			Severity:        model.SeverityMedium,
			Confidence:      0.4,
			LocationKey:     loc + "&id=1",
			LifecycleStatus: model.LifecycleUnconfirmed,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			EvidenceRefs:    []string{evUnconf},
			Title:           "Demo SQLi indicator (unconfirmed)",
		},
		{
			FindingID:         uuid.NewString(),
			RuleID:            "demo-info",
			Category:          "Informational",
			Severity:          model.SeverityInfo,
			Confidence:        0.99,
			LocationKey:       "GET " + demoBase + "/robots.txt",
			LifecycleStatus:   model.LifecycleFalsePositiveSuppressed,
			FirstSeenAt:       now,
			LastSeenAt:        now,
			EvidenceRefs:      []string{evSupp},
			Title:             "Demo suppressed finding",
			SuppressionReason: "baseline noise",
		},
	}
	evidence := []model.Evidence{
		{
			EvidenceID: evConfirmed,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepPassive,
			ContextID:  ctxID,
			Payload: model.HTTPRequestResponsePayload{
				Method:              "GET",
				URL:                 demoBase + "/search?q=%3Cscript%3E",
				StatusCode:          200,
				ResponseBodySnippet: "<html><script>alert(1)</script></html>",
			},
		},
		{
			EvidenceID: evUnconf,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepPassive,
			ContextID:  ctxID,
			Payload: model.HTTPRequestResponsePayload{
				Method:              "GET",
				URL:                 demoBase + "/search?q=1",
				StatusCode:          500,
				ResponseBodySnippet: "syntax error near",
			},
		},
		{
			EvidenceID: evSupp,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepPassive,
			ContextID:  ctxID,
			Payload: model.HTTPRequestResponsePayload{
				Method:     "GET",
				URL:        demoBase + "/robots.txt",
				StatusCode: 200,
			},
		},
	}
	return findings, evidence
}

func appendSQLiBuiltinTemplatePath(paths []string, configFileDir string) []string {
	if !payloads.SQLiEnabled() || strings.TrimSpace(configFileDir) == "" {
		return paths
	}
	t := filepath.Join(configFileDir, "templates", "sqli-query-probe.yaml")
	if _, err := os.Stat(t); err == nil {
		paths = append(paths, t)
	}
	return paths
}

func appendXSSBuiltinTemplatePath(paths []string, configFileDir string) []string {
	if !payloads.XSSEnabled() || strings.TrimSpace(configFileDir) == "" {
		return paths
	}
	t := filepath.Join(configFileDir, "templates", "xss-query-probe.yaml")
	if _, err := os.Stat(t); err == nil {
		paths = append(paths, t)
	}
	return paths
}

func katanaSeedURLs(cfg *config.ScanAsCode) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, t := range cfg.Targets {
		u := strings.TrimSpace(t.BaseURL)
		if u != "" {
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				out = append(out, u)
			}
		}
		for _, sp := range t.StartPoints {
			sp = strings.TrimSpace(sp)
			if sp == "" {
				continue
			}
			if _, ok := seen[sp]; !ok {
				seen[sp] = struct{}{}
				out = append(out, sp)
			}
		}
	}
	return out
}

func katanaHeadlessEnabled(step config.ScanStep) bool {
	if strings.TrimSpace(os.Getenv("DAST_KATANA_HEADLESS")) == "0" {
		return false
	}
	return step.KatanaHeadless
}

func katanaOptsFromStep(cfg *config.ScanAsCode, step config.ScanStep, seeds, headers []string) katana.CLIOptions {
	o := katana.CLIOptions{
		Targets:   seeds,
		Headers:   headers,
		Headless:  katanaHeadlessEnabled(step),
		ExtraArgs: step.KatanaExtraArgs,
		Dedupe:    cfg.Noise.Dedupe,
	}
	if step.KatanaDepth > 0 {
		o.Depth = step.KatanaDepth
	} else if cfg.Budgets.Discovery.MaxDepth > 0 {
		o.Depth = cfg.Budgets.Discovery.MaxDepth
	}
	if step.KatanaConcurrency > 0 {
		o.Concurrency = step.KatanaConcurrency
	} else if cfg.Budgets.Active.Concurrency > 0 {
		o.Concurrency = cfg.Budgets.Active.Concurrency
	}
	if step.KatanaTimeoutSecs > 0 {
		o.TimeoutSecs = step.KatanaTimeoutSecs
	}
	if step.KatanaRateLimit > 0 {
		o.RateLimit = step.KatanaRateLimit
	} else if cfg.Budgets.Active.RateLimitRps > 0 {
		o.RateLimit = cfg.Budgets.Active.RateLimitRps
	}
	if d := strings.TrimSpace(step.KatanaCrawlDuration); d != "" {
		o.CrawlDuration = d
	} else if cfg.Budgets.Discovery.DurationCrawlSecs > 0 {
		o.CrawlDuration = fmt.Sprintf("%ds", cfg.Budgets.Discovery.DurationCrawlSecs)
	}
	if cfg.Budgets.Discovery.MaxURLs > 0 {
		o.MaxURLs = cfg.Budgets.Discovery.MaxURLs
	}
	for _, re := range cfg.Scope.Allow {
		re = strings.TrimSpace(re)
		if re != "" {
			o.CrawlScope = append(o.CrawlScope, re)
		}
	}
	for _, re := range cfg.Scope.Deny {
		re = strings.TrimSpace(re)
		if re != "" {
			o.CrawlOutScope = append(o.CrawlOutScope, re)
		}
	}
	return o
}

func nucleiUseOfficialCLI(step config.ScanStep) bool {
	return strings.EqualFold(strings.TrimSpace(step.NucleiEngine), "cli")
}

func existingPaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// mergeOfficialNucleiDirs добавляет каталог из DAST_NUCLEI_TEMPLATES_DIR и /opt/nuclei-templates (Docker),
// чтобы UI-сканы находили community-шаблоны даже при кастомном YAML.
func mergeOfficialNucleiDirs(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range in {
		add(p)
	}
	if v := strings.TrimSpace(os.Getenv("DAST_NUCLEI_TEMPLATES_DIR")); v != "" {
		add(v)
	}
	add("/opt/nuclei-templates")
	return out
}

func resolveTemplatePaths(configDir string, paths []string, workDir string) []string {
	repoRoot := filepath.Clean(filepath.Join(workDir, ".."))
	if len(paths) == 0 {
		for _, d := range []string{filepath.Join(repoRoot, "templates"), filepath.Join(workDir, "templates")} {
			if pathExists(d) {
				return []string{d}
			}
		}
		return []string{filepath.Join(workDir, "templates")}
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			out = append(out, p)
			continue
		}
		if resolved := resolveOneRelativeTemplatePath(configDir, p, workDir, repoRoot); resolved != "" {
			out = append(out, resolved)
			continue
		}
		if configDir != "" {
			out = append(out, filepath.Join(configDir, p))
			continue
		}
		out = append(out, p)
	}
	return out
}

func resolveOneRelativeTemplatePath(configDir, p, workDir, repoRoot string) string {
	candidates := []string{}
	if configDir != "" {
		candidates = append(candidates, filepath.Join(configDir, p))
	}
	candidates = append(candidates, filepath.Join(repoRoot, p), filepath.Join(workDir, p), p)
	for _, c := range candidates {
		if pathExists(c) {
			return c
		}
	}
	return ""
}

func extractEndpoint(e model.Evidence) string {
	rawURL := ""
	switch p := e.Payload.(type) {
	case model.HTTPRequestResponsePayload:
		rawURL = p.URL
	case map[string]any:
		if v, ok := p["url"].(string); ok {
			rawURL = v
		}
	}
	if rawURL == "" {
		return ""
	}
	u, err := parseURL(rawURL)
	if err != nil {
		return ""
	}
	if noise.IsAttackPayloadURL(rawURL) {
		return ""
	}
	u.RawQuery = ""
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		if strings.HasPrefix(raw, "//") {
			return url.Parse("https:" + raw)
		}
		if strings.HasPrefix(raw, "/") {
			return url.Parse("http://localhost" + raw)
		}
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return nil, fmt.Errorf("empty host in URL: %s", raw)
	}
	return u, nil
}
