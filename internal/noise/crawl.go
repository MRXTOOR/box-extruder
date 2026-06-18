package noise

import "github.com/box-extruder/dast/internal/model"

// IsCrawlTelemetryFinding is true for Katana/ZAP URL inventory rows — not security findings.
func IsCrawlTelemetryFinding(f model.Finding) bool {
	if f.Category == "crawl-discovery" {
		return true
	}
	switch f.RuleID {
	case "katana:discovered-url", "zap:discovered-url":
		return true
	default:
		return false
	}
}
