package webscan

import (
	"fmt"
	"strings"

	"github.com/box-extruder/dast/internal/auth/discovery"
	"github.com/box-extruder/dast/internal/config"
	"gopkg.in/yaml.v3"
)

// CreateOptions carries UI scan parameters for building scan-as-code YAML.
type CreateOptions struct {
	JobID     string
	Target    string
	Login     string
	Password  string
	AuthURL   string
	VerifyURL string

	KatanaDepth      *int
	KatanaMaxURLs    *int
	ZapSpiderMinutes *int
	ZapPassiveSecs   *int
	StartPoints      []string

	InsecureSkipTLSVerify bool
}

// BuildScanYAML builds a full scan-as-code document for enterprise web scans.
func BuildScanYAML(opts CreateOptions) ([]byte, error) {
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		return nil, fmt.Errorf("targetUrl is required")
	}

	cfg := config.DefaultScanAsCode()
	cfg.Job.Name = strings.TrimSpace(opts.JobID)
	if cfg.Job.Name == "" {
		cfg.Job.Name = "web-scan"
	}
	cfg.InsecureSkipTLSVerify = opts.InsecureSkipTLSVerify

	starts := []string{target}
	for _, sp := range opts.StartPoints {
		sp = strings.TrimSpace(sp)
		if sp != "" {
			starts = append(starts, sp)
		}
	}
	cfg.Targets = []config.Target{{
		Type:        "web",
		BaseURL:     target,
		StartPoints: starts,
	}}
	cfg.Scope.Allow = []string{scopeRegexFromBase(target)}
	cfg.Scope.Deny = nil

	// Deeper defaults for UI-driven scans (Katana uses budgets for -max-urls; step depth overrides -d).
	cfg.Budgets.Discovery.MaxDepth = 6
	cfg.Budgets.Discovery.MaxURLs = 3000
	cfg.Budgets.Discovery.DurationCrawlSecs = 120
	if opts.KatanaDepth != nil && *opts.KatanaDepth > 0 {
		cfg.Budgets.Discovery.MaxDepth = *opts.KatanaDepth
	}
	if opts.KatanaMaxURLs != nil && *opts.KatanaMaxURLs > 0 {
		cfg.Budgets.Discovery.MaxURLs = *opts.KatanaMaxURLs
	}

	katDepth := cfg.Budgets.Discovery.MaxDepth
	zapSpiderMin := 15
	if opts.ZapSpiderMinutes != nil && *opts.ZapSpiderMinutes > 0 {
		zapSpiderMin = *opts.ZapSpiderMinutes
	}
	passiveWait := 90
	if opts.ZapPassiveSecs != nil && *opts.ZapPassiveSecs > 0 {
		passiveWait = *opts.ZapPassiveSecs
	}

	login := strings.TrimSpace(opts.Login)
	pass := strings.TrimSpace(opts.Password)
	authURL := strings.TrimSpace(opts.AuthURL)
	if login != "" || pass != "" {
		if login == "" || pass == "" {
			return nil, fmt.Errorf("login and password are both required for authenticated scan")
		}
		if authURL == "" {
			return nil, fmt.Errorf("authUrl is required when using credentials (login URL auto-discovery was removed)")
		}
		disc := discovery.Discover(discovery.Request{
			TargetURL:             target,
			AuthURL:               authURL,
			VerifyURL:             strings.TrimSpace(opts.VerifyURL),
			Login:                 login,
			Password:              pass,
			InsecureSkipTLSVerify: opts.InsecureSkipTLSVerify,
		})
		if !disc.Verified || disc.GenericLogin == nil {
			msg := strings.TrimSpace(disc.Error)
			if msg == "" {
				msg = "authentication failed; check authUrl, credentials, and optional verifyUrl"
			}
			return nil, fmt.Errorf("%s", msg)
		}
		cfg.Auth = &config.Auth{
			Strategy: "providerChain",
			Providers: []config.AuthProvider{{
				Type: "genericLogin",
				ID:   "ui-login",
				SecretsRef: map[string]string{
					"username": login,
					"password": pass,
				},
				GenericLogin: disc.GenericLogin,
			}},
		}
	}

	cfg.Scan.Plan = []config.ScanStep{
		{StepType: "katana", Enabled: true, KatanaDepth: katDepth},
		{
			StepType:                    "nucleiTemplates",
			Enabled:                     true,
			NucleiEngine:                "cli",
			TemplatePaths:               []string{"/opt/nuclei-templates"},
			NucleiIncludeDiscoveredURLs: true,
			NucleiRateLimit:             50,
			NucleiExtraArgs:             []string{"-severity", "critical,high,medium,low"},
		},
		{
			StepType:               "zapBaseline",
			Enabled:                true,
			ZAPAutomationFramework: true,
			ZAPSpiderTraditional:   true,
			ZAPMaxSpiderMinutes:    zapSpiderMin,
			ZAPPassiveWaitSeconds:  passiveWait,
		},
		{
			StepType:                    "nucleiTemplates",
			Enabled:                     true,
			NucleiEngine:                "cli",
			TemplatePaths:               []string{"/opt/nuclei-templates"},
			NucleiIncludeDiscoveredURLs: true,
			NucleiRateLimit:             50,
			NucleiExtraArgs:             []string{"-severity", "critical,high,medium,low"},
		},
	}
	cfg.NucleiFollowUp = nil

	return yaml.Marshal(cfg)
}

func scopeRegexFromBase(raw string) string {
	s := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	repl := strings.NewReplacer(
		".", "\\.", "?", "\\?", "+", "\\+", "*", "\\*",
		"(", "\\(", ")", "\\)", "[", "\\[", "]", "\\]",
		"{", "\\{", "}", "\\}", "|", "\\|", "^", "\\^", "$", "\\$",
	)
	return "^" + repl.Replace(s) + "/.*"
}
