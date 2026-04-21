package runner

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/storage"
)

func harvestHTTPURLsFromFindings(findings []model.Finding, ev map[string]model.Evidence) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, f := range findings {
		for _, eid := range f.EvidenceRefs {
			e, ok := ev[eid]
			if !ok || e.Type != model.EvidenceHTTPRequestResponse {
				continue
			}
			pl, ok := e.Payload.(model.HTTPRequestResponsePayload)
			if !ok {
				continue
			}
			u := strings.TrimSpace(pl.URL)
			if u == "" {
				continue
			}
			if _, dup := seen[u]; dup {
				continue
			}
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

func feedAppend(seen map[string]struct{}, feed *[]string, urls []string) {
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		*feed = append(*feed, u)
	}
}

func nucleiTargetCap(cfg *config.ScanAsCode) int {
	if cfg == nil {
		return 500
	}
	if cfg.Scope.MaxURLs > 0 {
		return cfg.Scope.MaxURLs
	}
	if cfg.Budgets.Discovery.MaxURLs > 0 {
		return cfg.Budgets.Discovery.MaxURLs
	}
	return 500
}

func nucleiCLITargetLines(cfg *config.ScanAsCode, bases []string, discoveryFeed []string, include bool) []string {
	capN := nucleiTargetCap(cfg)
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || len(out) >= capN {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, b := range bases {
		add(b)
	}
	if !include {
		return out
	}
	for _, u := range discoveryFeed {
		add(u)
	}
	return out
}

func nucleiBuiltinBases(cfg *config.ScanAsCode, bases []string, discoveryFeed []string, include bool) []string {
	maxO := nucleiBuiltinOriginCap(cfg)
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		key := originKey(raw)
		if key == "" {
			key = strings.TrimRight(raw, "/")
		}
		if _, ok := seen[key]; ok {
			return
		}
		if len(out) >= maxO {
			return
		}
		seen[key] = struct{}{}
		out = append(out, normalizeBaseURL(raw))
	}
	for _, b := range bases {
		add(b)
	}
	if !include {
		return out
	}
	for _, u := range discoveryFeed {
		add(u)
	}
	return out
}

func nucleiBuiltinOriginCap(cfg *config.ScanAsCode) int {
	if cfg == nil {
		return 48
	}
	n := 48
	if cfg.Scope.MaxURLs > 0 && cfg.Scope.MaxURLs < n {
		n = cfg.Scope.MaxURLs
	}
	if cfg.Budgets.Discovery.MaxURLs > 0 && cfg.Budgets.Discovery.MaxURLs < n {
		n = cfg.Budgets.Discovery.MaxURLs
	}
	if n < 1 {
		n = 1
	}
	return n
}

func originKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func normalizeBaseURL(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimRight(s, "/")
	return s
}

func writeNucleiTargetsFile(workDir, jobID string, lines []string) (string, error) {
	path := filepath.Join(storage.JobRoot(workDir, jobID), "nuclei-targets.txt")
	var b strings.Builder
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("nuclei targets: empty list")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
