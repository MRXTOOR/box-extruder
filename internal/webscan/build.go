package webscan

import (
	"fmt"
	"net/url"
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
	baseTarget, err := normalizeTargetBase(target)
	if err != nil {
		return nil, err
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
	// If user entered a deep URL (/login, /app/home), also seed the site root.
	if baseTarget != target {
		starts = append(starts, baseTarget)
	}
	cfg.Targets = []config.Target{{
		Type:        "web",
		BaseURL:     baseTarget,
		StartPoints: starts,
	}}
	cfg.Scope.Allow = []string{scopeRegexFromBase(baseTarget)}
	cfg.Scope.Deny = []string{
		`.*\.(ttf|woff2?|eot|otf|png|jpg|jpeg|gif|svg|ico|webp|mp4|mp3|pdf|zip|gz)(\?.*)?$`,
	}

	// Deeper defaults for UI-driven scans (Katana uses budgets for -max-urls; step depth overrides -d).
	cfg.Budgets.Discovery.MaxDepth = 6
	cfg.Budgets.Discovery.MaxURLs = 3000
	cfg.Budgets.Discovery.DurationCrawlSecs = 120
	cfg.Budgets.Discovery.PreserveQuery = true
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
	passiveWait := 180
	if opts.ZapPassiveSecs != nil && *opts.ZapPassiveSecs > 0 {
		passiveWait = *opts.ZapPassiveSecs
	}

	login := strings.TrimSpace(opts.Login)
	// Keep password as-is: leading/trailing spaces can be part of valid credentials.
	pass := opts.Password
	authURL := strings.TrimSpace(opts.AuthURL)
	if login != "" || pass != "" {
		if login == "" || pass == "" {
			return nil, fmt.Errorf("login and password are both required for authenticated scan")
		}
		if authURL == "" {
			return nil, fmt.Errorf("authUrl is required when using credentials (login URL auto-discovery was removed)")
		}
		disc := discovery.Discover(discovery.Request{
			TargetURL:             baseTarget,
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
	if len(cfg.Targets) > 0 {
		var inferred []string
		if cfg.Auth != nil {
			for _, p := range cfg.Auth.Providers {
				if p.GenericLogin != nil {
					inferred = append(inferred, inferStartPointsFromLoginURL(p.GenericLogin.LoginURL)...)
				}
			}
		}
		if v := strings.TrimSpace(opts.VerifyURL); v != "" {
			inferred = append(inferred, v)
		}
		if len(inferred) > 0 {
			cfg.Targets[0].StartPoints = mergeStartPoints(cfg.Targets[0].StartPoints, inferred)
		}
	}

	katanaStep := config.ScanStep{
		StepType:        "katana",
		Enabled:         true,
		KatanaDepth:     katDepth,
		KatanaHeadless:  true,
		KatanaExtraArgs: []string{"-jc"},
	}

	cfg.Scan.Plan = []config.ScanStep{
		katanaStep,
		{
			StepType:               "zapBaseline",
			Enabled:                true,
			ZAPAutomationFramework: true,
			ZAPSpiderTraditional:   true,
			// SPA targets (like Juice Shop) require Ajax spider to discover in-app routes/endpoints.
			ZAPSpiderAjax:           true,
			ZAPMaxSpiderMinutes:     zapSpiderMin,
			ZAPPassiveWaitSeconds:   passiveWait,
			ZAPContextExcludeStatic: true,
			ZAPAjaxEventWait:        1000,
			ZAPAjaxReloadWait:       1000,
		},
		{
			StepType:        "wapiti",
			Enabled:         true,
			WapitiScanForce: "normal",
			WapitiTimeout:   900,
		},
		{
			StepType:                    "nucleiTemplates",
			Enabled:                     true,
			NucleiEngine:                "cli",
			TemplatePaths:               []string{"/opt/nuclei-templates"},
			NucleiIncludeDiscoveredURLs: true,
			NucleiRateLimit:             50,
			NucleiExtraArgs: []string{
				"-severity", "critical,high,medium,low",
				"-ni",
				"-timeout", "5",
				"-retries", "0",
			},
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
	// Include both the base URL itself and any nested path.
	return "^" + repl.Replace(s) + "(/.*)?$"
}

func normalizeTargetBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid targetUrl: expected absolute http(s) URL")
	}
	return u.Scheme + "://" + u.Host, nil
}
