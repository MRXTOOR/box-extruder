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

	applyTargetsAndScope(&cfg, target, baseTarget, opts.StartPoints)
	katDepth := applyDiscoveryBudgets(&cfg, opts)
	zapSpiderMin, passiveWait := zapTimings(opts)

	if err := applyAuth(&cfg, opts, baseTarget); err != nil {
		return nil, err
	}
	applyInferredStartPoints(&cfg, opts)

	cfg.Scan.Plan = buildScanPlan(katDepth, zapSpiderMin, passiveWait)
	cfg.NucleiFollowUp = nil
	return yaml.Marshal(cfg)
}

// applyTargetsAndScope seeds the target start points and scope allow/deny rules.
func applyTargetsAndScope(cfg *config.ScanAsCode, target, baseTarget string, startPoints []string) {
	starts := []string{target}
	for _, sp := range startPoints {
		if sp = strings.TrimSpace(sp); sp != "" {
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
}

// applyDiscoveryBudgets sets the crawl budgets (with UI overrides) and returns
// the effective Katana depth.
func applyDiscoveryBudgets(cfg *config.ScanAsCode, opts CreateOptions) int {
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
	return cfg.Budgets.Discovery.MaxDepth
}

// zapTimings resolves the ZAP spider minutes and passive wait seconds.
func zapTimings(opts CreateOptions) (spiderMinutes, passiveWaitSecs int) {
	spiderMinutes = 15
	if opts.ZapSpiderMinutes != nil && *opts.ZapSpiderMinutes > 0 {
		spiderMinutes = *opts.ZapSpiderMinutes
	}
	passiveWaitSecs = 180
	if opts.ZapPassiveSecs != nil && *opts.ZapPassiveSecs > 0 {
		passiveWaitSecs = *opts.ZapPassiveSecs
	}
	return spiderMinutes, passiveWaitSecs
}

// applyAuth runs login discovery and wires the generic-login provider when
// credentials are supplied.
func applyAuth(cfg *config.ScanAsCode, opts CreateOptions, baseTarget string) error {
	login := strings.TrimSpace(opts.Login)
	// Keep password as-is: leading/trailing spaces can be part of valid credentials.
	pass := opts.Password
	if login == "" && pass == "" {
		return nil
	}
	if login == "" || pass == "" {
		return fmt.Errorf("login and password are both required for authenticated scan")
	}
	disc := discovery.Discover(discovery.Request{
		TargetURL:             strings.TrimSpace(opts.Target),
		AuthURL:               strings.TrimSpace(opts.AuthURL),
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
		return fmt.Errorf("%s", msg)
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
	return nil
}

// applyInferredStartPoints adds start points inferred from the login/verify URLs.
func applyInferredStartPoints(cfg *config.ScanAsCode, opts CreateOptions) {
	if len(cfg.Targets) == 0 {
		return
	}
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

// buildScanPlan assembles the default katana → ZAP → wapiti → nuclei plan.
func buildScanPlan(katDepth, zapSpiderMin, passiveWait int) []config.ScanStep {
	return []config.ScanStep{
		{
			StepType:        "katana",
			Enabled:         true,
			KatanaDepth:     katDepth,
			KatanaHeadless:  true,
			KatanaExtraArgs: []string{"-jc"},
		},
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
