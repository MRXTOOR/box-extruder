package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ParseScanAsCode parses YAML or JSON-like YAML into ScanAsCode.
func ParseScanAsCode(data []byte) (*ScanAsCode, error) {
	var c ScanAsCode
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse scan-as-code: %w", err)
	}
	MergeDefaults(&c)
	if len(c.Targets) == 0 {
		return nil, fmt.Errorf("targets: at least one target required")
	}
	for _, t := range c.Targets {
		if t.BaseURL == "" {
			return nil, fmt.Errorf("target baseUrl required")
		}
	}
	return &c, nil
}
