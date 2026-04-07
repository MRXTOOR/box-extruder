package config

import "github.com/box-extruder/dast/internal/model"

// EffectivePlan returns enabled steps in order; preset expands if Plan empty.
func EffectivePlan(cfg ScanAsCode) []ScanStep {
	if len(cfg.Scan.Plan) > 0 {
		var out []ScanStep
		for _, s := range cfg.Scan.Plan {
			if s.Enabled {
				out = append(out, s)
			}
		}
		return out
	}
	switch cfg.Scan.Preset {
	case "Deep":
		return []ScanStep{
			{StepType: string(model.StepCrawl), Enabled: true},
			{StepType: string(model.StepPassive), Enabled: true},
			{StepType: string(model.StepFullActive), Enabled: true},
			{StepType: string(model.StepVerification), Enabled: true},
		}
	case "Standard":
		return []ScanStep{
			{StepType: string(model.StepCrawl), Enabled: true},
			{StepType: string(model.StepPassive), Enabled: true},
			{StepType: string(model.StepTargetedActive), Enabled: true},
			{StepType: string(model.StepVerification), Enabled: true},
		}
	default: // Fast
		return []ScanStep{
			{StepType: string(model.StepCrawl), Enabled: true},
			{StepType: string(model.StepPassive), Enabled: true},
			{StepType: string(model.StepVerification), Enabled: true},
		}
	}
}
