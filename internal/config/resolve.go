package config

import (
	"fmt"
	"os"
	"strings"
)

// ResolveSecretRef turns secret://ENV_NAME into os.Getenv(ENV_NAME).
func ResolveSecretRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}
	if strings.HasPrefix(ref, "secret://") {
		key := strings.TrimPrefix(ref, "secret://")
		v := os.Getenv(key)
		if v == "" {
			return "", fmt.Errorf("secret env %q not set", key)
		}
		return v, nil
	}
	return ref, nil
}

// MergeDefaults fills missing nested defaults from cfg (mutates in place).
func MergeDefaults(cfg *ScanAsCode) {
	d := DefaultScanAsCode()
	if cfg.Version == "" {
		cfg.Version = d.Version
	}
	if cfg.Job.Name == "" {
		cfg.Job.Name = d.Job.Name
	}
	if cfg.Budgets.Discovery.MaxDepth == 0 && cfg.Budgets.Discovery.MaxURLs == 0 && cfg.Budgets.Discovery.DurationCrawlSecs == 0 {
		cfg.Budgets.Discovery = d.Budgets.Discovery
	}
	if cfg.Budgets.Passive.PassiveWaitDelaySecs == 0 && cfg.Budgets.Passive.PassiveRuleDefaultSeverity == "" {
		cfg.Budgets.Passive = d.Budgets.Passive
	}
	if cfg.Budgets.Active.MaxRequestsTotal == 0 && cfg.Budgets.Active.Concurrency == 0 {
		cfg.Budgets.Active = d.Budgets.Active
	}
	if cfg.Budgets.Verification.MaxVerifications == 0 {
		cfg.Budgets.Verification = d.Budgets.Verification
	}
	if cfg.Noise.Dedupe.LocationKey == "" {
		cfg.Noise.Dedupe = d.Noise.Dedupe
	}
	if cfg.Noise.FalsePositive.ProgressiveConfirmation == nil {
		cfg.Noise.FalsePositive.ProgressiveConfirmation = d.Noise.FalsePositive.ProgressiveConfirmation
	}
	if cfg.Noise.FalsePositive.VerifyOnlyNewOrChanged == nil {
		cfg.Noise.FalsePositive.VerifyOnlyNewOrChanged = d.Noise.FalsePositive.VerifyOnlyNewOrChanged
	}
	if len(cfg.Outputs.Formats) == 0 {
		cfg.Outputs.Formats = d.Outputs.Formats
	}
	if cfg.Outputs.Paths.ArtifactsDir == "" {
		cfg.Outputs.Paths = d.Outputs.Paths
	}
}
