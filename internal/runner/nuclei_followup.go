package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/storage"
	"gopkg.in/yaml.v3"
)

const nucleiKatanaSeedsFile = "nuclei-katana-seeds.txt"

// FollowUpEnqueueRequest — вторая задача в очереди (только Nuclei по URL из краула).
type FollowUpEnqueueRequest struct {
	JobID      string
	UserID     string
	TargetURL  string
	ConfigYAML []byte
	ConfigHash string
}

func collectNucleiSeedLines(cfg *config.ScanAsCode, discoveryFeed []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	for _, t := range cfg.Targets {
		add(t.BaseURL)
		for _, sp := range t.StartPoints {
			add(sp)
		}
	}
	for _, u := range discoveryFeed {
		add(u)
	}
	return out
}

func writeNucleiKatanaSeedsFile(workDir, jobID string, lines []string) (string, error) {
	path := filepath.Join(storage.JobRoot(workDir, jobID), nucleiKatanaSeedsFile)
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
		return "", fmt.Errorf("nuclei seeds: empty URL list")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func buildNucleiFollowUpYAML(parent *config.ScanAsCode, listAbs, followJobID string) ([]byte, error) {
	if parent == nil {
		return nil, fmt.Errorf("parent config required")
	}
	fu := parent.NucleiFollowUp
	if fu == nil {
		return nil, fmt.Errorf("nucleiFollowUp not configured")
	}
	engine := strings.TrimSpace(fu.NucleiEngine)
	if engine == "" {
		engine = "cli"
	}
	tpl := fu.TemplatePaths
	if len(tpl) == 0 {
		tpl = []string{"/opt/nuclei-templates"}
	}
	step := config.ScanStep{
		StepType:                    "nucleiTemplates",
		Enabled:                     true,
		NucleiEngine:                engine,
		TemplatePaths:               tpl,
		NucleiListFile:              listAbs,
		NucleiIncludeDiscoveredURLs: false,
		NucleiExtraArgs:             fu.NucleiExtraArgs,
		NucleiRateLimit:             fu.NucleiRateLimit,
	}
	child := config.ScanAsCode{
		Version:               parent.Version,
		Job:                   config.JobMeta{Name: followJobID + "-nuclei", ID: followJobID},
		Targets:               parent.Targets,
		Scope:                 parent.Scope,
		Auth:                  parent.Auth,
		Budgets:               parent.Budgets,
		Noise:                 parent.Noise,
		Outputs:               parent.Outputs,
		Execution:             parent.Execution,
		InsecureSkipTLSVerify: parent.InsecureSkipTLSVerify,
		Scan: config.Scan{
			Plan: []config.ScanStep{step},
		},
	}
	if strings.TrimSpace(child.Version) == "" {
		child.Version = "1.0"
	}
	return yaml.Marshal(&child)
}

func shouldEnqueueNucleiFollowUp(cfg *config.ScanAsCode, opt Options) bool {
	if cfg == nil || cfg.NucleiFollowUp == nil || !cfg.NucleiFollowUp.Enabled {
		return false
	}
	if opt.OnFollowUpEnqueue == nil || strings.TrimSpace(opt.UserID) == "" {
		return false
	}
	return true
}

// resolveNucleiListFilePath возвращает абсолютный путь к файлу целей Nuclei (-l).
func resolveNucleiListFilePath(workDir, jobID, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw)
	}
	return filepath.Clean(filepath.Join(storage.JobRoot(workDir, jobID), raw))
}
