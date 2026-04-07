package exitcode

import (
	"os"
	"strings"

	"github.com/box-extruder/dast/internal/model"
)

// FromFindings returns non-zero if policy matches confirmed severities.
func FromFindings(findings []model.Finding) int {
	policy := os.Getenv("DAST_FAIL_ON_SEVERITY")
	if policy == "" {
		policy = "HIGH"
	}
	threshold := parseSeverityFloor(policy)
	for _, f := range findings {
		if f.LifecycleStatus != model.LifecycleConfirmed {
			continue
		}
		if severityRank(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}

func parseSeverityFloor(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 4
	}
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}
