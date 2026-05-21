package zap

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/google/uuid"
)

const urlsExportFileName = "zap-export-urls.txt"

// URLExportFindings reads ZAP automation export (type=url) and returns crawl-discovery findings.
func URLExportFindings(path string, ctxID string, dedupe config.DedupeConfig) ([]model.Finding, []model.Evidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return ParseURLExportData(data, ctxID, dedupe)
}

// ParseURLExportData parses export output: one URL per line (optional # comments).
func ParseURLExportData(data []byte, ctxID string, dedupe config.DedupeConfig) ([]model.Finding, []model.Evidence, error) {
	var findings []model.Finding
	var evidence []model.Evidence
	now := time.Now().UTC()
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u := strings.TrimSpace(line)
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		evID := uuid.NewString()
		locKey := noise.BuildLocationKeyFromHTTP(dedupe, "GET", u)
		f := model.Finding{
			FindingID:       uuid.NewString(),
			RuleID:          "zap:discovered-url",
			Category:        "crawl-discovery",
			Severity:        model.SeverityInfo,
			Confidence:      0.7,
			LocationKey:     locKey,
			LifecycleStatus: model.LifecycleDetected,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			EvidenceRefs:    []string{evID},
			Title:           "ZAP: обнаружен URL",
			Description:     "export job (sites tree)",
		}
		ev := model.Evidence{
			EvidenceID: evID,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepZAPBaseline,
			ContextID:  ctxID,
			Payload: model.HTTPRequestResponsePayload{
				Method: "GET",
				URL:    u,
			},
		}
		findings = append(findings, f)
		evidence = append(evidence, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("zap url export: %w", err)
	}
	return findings, evidence, nil
}

func dedupeSeedURLs(urls []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}
