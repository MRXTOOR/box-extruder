package zap

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	automationFilename = "automation.yaml"
	reportFileName     = "zap-report.json"
	autorunLogFileName = "zap-autorun.log"
	dastContextName    = "dast"
)

// UseAutomation returns true if this step should run ZAP via Automation Framework (spider / Ajax spider / report).
func UseAutomation(step config.ScanStep) bool {
	if strings.TrimSpace(step.ZAPAutomationFile) != "" {
		return true
	}
	if step.ZAPAutomationFramework {
		return true
	}
	return step.ZAPSpiderAjax
}

func RunAutomation(
	seedURLs []string,
	outDir, dockerImage, configFileDir string,
	allow []string,
	step config.ScanStep,
	authHeaders map[string]string,
	sqlPayloadPath, xssPayloadPath string,
	contextID string,
	dedupe config.DedupeConfig,
) ([]model.Finding, []model.Evidence, error) {
	if dockerImage == "" {
		dockerImage = "ghcr.io/zaproxy/zaproxy:stable"
	}
	if img := os.Getenv("DAST_ZAP_DOCKER_IMAGE"); img != "" {
		dockerImage = img
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, nil, err
	}
	seedURLs = dedupeSeedURLs(seedURLs)
	if len(seedURLs) == 0 {
		return nil, nil, fmt.Errorf("zap automation: no seed URLs")
	}

	var yamlBytes []byte
	var err error
	var zapDockerExtra []string
	if p := strings.TrimSpace(step.ZAPAutomationFile); p != "" {
		full := p
		if !filepath.IsAbs(p) && configFileDir != "" {
			full = filepath.Join(configFileDir, p)
		}
		yamlBytes, err = os.ReadFile(full)
		if err != nil {
			return nil, nil, fmt.Errorf("zap automation file: %w", err)
		}
	} else {
		absOut, _ := filepath.Abs(outDir)
		reportDir := "/zap/wrk"
		if useLocalZAP() {
			reportDir = absOut
		}
		remapped := make([]string, 0, len(seedURLs))
		var za []string
		for _, s := range seedURLs {
			zs, a, extra := remapLocalhostForZAPDocker(s, allow)
			remapped = append(remapped, zs)
			if len(a) > len(za) {
				za = a
			}
			if len(extra) > 0 {
				zapDockerExtra = extra
			}
		}
		remapped = dedupeSeedURLs(remapped)
		probeBase := remapped[0]
		probes := BuildMergedPayloadProbes(probeBase, authHeaders, sqlPayloadPath, xssPayloadPath)
		yamlBytes, err = buildAutomationYAML(remapped, za, step, reportDir, authHeaders, probes)
		if err != nil {
			return nil, nil, err
		}
	}

	autoPath := filepath.Join(outDir, automationFilename)
	if err := os.WriteFile(autoPath, yamlBytes, 0o644); err != nil {
		return nil, nil, err
	}

	reportPath := filepath.Join(outDir, reportFileName)
	exportPath := filepath.Join(outDir, urlsExportFileName)
	runErr := runZAPAutorun(outDir, dockerImage, useLocalZAP(), zapDockerExtra)

	var findings []model.Finding
	var evidence []model.Evidence

	data, err := os.ReadFile(reportPath)
	if err != nil {
		if runErr != nil {
			return nil, nil, runErr
		}
		return nil, nil, fmt.Errorf("zap automation: отчёт не найден %s: %w", reportPath, err)
	}
	f, e, perr := ParseReportJSON(data)
	if perr != nil {
		return nil, nil, perr
	}
	findings = append(findings, f...)
	evidence = append(evidence, e...)

	if ef, ee, exErr := URLExportFindings(exportPath, contextID, dedupe); exErr == nil && len(ef) > 0 {
		findings = append(findings, ef...)
		evidence = append(evidence, ee...)
	} else if _, statErr := os.Stat(exportPath); statErr != nil {
		// Export job missing or failed (old worker image or Import/Export add-on). Alerts-only feed remains.
		_ = statErr
	}
	// runErr may be non-nil when probes time out but report/export exist
	_ = runErr
	return findings, evidence, nil
}

func useLocalZAP() bool {
	return strings.TrimSpace(os.Getenv("DAST_ZAP_LOCAL")) == "1"
}

// staticSpiderSeedExts lists URL path suffixes that are never useful as spider seed pages.
// JS/CSS/image files result in trivially-fast spider instances that waste concurrency.
var staticSpiderSeedExts = []string{
	".js", ".mjs", ".css", ".map",
	".json", ".xml", ".txt",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
	".ttf", ".woff", ".woff2", ".eot", ".otf",
	".pdf", ".zip", ".gz", ".tar", ".rar",
	".mp4", ".mp3", ".avi", ".mov", ".webm",
}

// apiPathPrefixes are URL path prefixes that indicate a JSON/REST API endpoint.
// The Ajax spider opens URLs in a real browser: visiting an API endpoint shows raw JSON,
// there are no navigation links, so the spider exits in <1 second — wasting concurrency.
var apiPathPrefixes = []string{
	"/api/", "/service/", "/locales/",
}

// isPageLikeURL returns false for URLs that are not useful as spider/spiderAjax seeds:
//   - URLs ending with a known static asset extension (.js, .css, .png, …)
//   - URLs whose path starts with an API/service prefix (return JSON, not HTML)
func isPageLikeURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	p := strings.ToLower(u.Path)
	for _, ext := range staticSpiderSeedExts {
		if strings.HasSuffix(p, ext) {
			return false
		}
	}
	for _, prefix := range apiPathPrefixes {
		if strings.HasPrefix(p, prefix) || strings.Contains(p, prefix) {
			return false
		}
	}
	return true
}

// filterPageSeeds returns only page-like URLs from seeds, preserving order.
// If the filter removes everything, the first seed is returned as-is (fallback).
func filterPageSeeds(seeds []string) []string {
	var out []string
	for _, s := range seeds {
		if isPageLikeURL(s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 && len(seeds) > 0 {
		return seeds[:1]
	}
	return out
}

func buildSPAContextExcludePaths() []string {
	return []string{
		`.*/static/js/[^/]+\.js(\?.*)?$`,
		`.*/static/css/[^/]+\.css(\?.*)?$`,
		`.*/static/media/.*`,
		`.*\.(ttf|woff2?|eot|otf|png|jpg|jpeg|gif|svg|ico|webp|mp4|mp3|pdf)(\?.*)?$`,
		`.*/remoteEntry\.js(\?.*)?$`,
	}
}

func buildReplacerJobFromAuthHeaders(authHeaders map[string]string) map[string]any {
	if len(authHeaders) == 0 {
		return nil
	}
	names := make([]string, 0, len(authHeaders))
	for k := range authHeaders {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	var rules []map[string]any
	for _, name := range names {
		val := strings.TrimSpace(authHeaders[name])
		if val == "" {
			continue
		}
		rules = append(rules, map[string]any{
			"description":       "DAST auth header " + name,
			"matchType":         "req_header",
			"matchRegex":        false,
			"matchString":       name,
			"replacementString": val,
		})
	}
	if len(rules) == 0 {
		return nil
	}
	return map[string]any{
		"type": "replacer",
		"parameters": map[string]any{
			"deleteAllRules": false,
		},
		"rules": rules,
	}
}

func buildAutomationYAML(seedURLs []string, allow []string, step config.ScanStep, reportDir string, authHeaders map[string]string, sqlProbes []map[string]any) ([]byte, error) {
	plan := newZapJobPlan(seedURLs, step, reportDir, sqlProbes)

	contextBlock := map[string]any{
		"name":         dastContextName,
		"urls":         seedURLs,
		"includePaths": buildIncludePaths(allow, plan.primary),
	}
	if step.ZAPContextExcludeStatic {
		contextBlock["excludePaths"] = buildSPAContextExcludePaths()
	}

	doc := map[string]any{
		"env": map[string]any{
			"contexts": []any{
				contextBlock,
			},
			"parameters": map[string]any{
				"failOnError":      false,
				"failOnWarning":    false,
				"progressToStdout": true,
			},
		},
		"jobs": plan.buildJobs(authHeaders),
	}
	return yaml.Marshal(doc)
}

// zapJobPlan holds the resolved parameters for assembling the ZAP automation jobs.
type zapJobPlan struct {
	pageSeeds  []string
	primary    string
	step       config.ScanStep
	maxSpider  int
	passiveMin int
	browser    string
	useTrad    bool
	useAjax    bool
	reportDir  string
	sqlProbes  []map[string]any
}

func newZapJobPlan(seedURLs []string, step config.ScanStep, reportDir string, sqlProbes []map[string]any) zapJobPlan {
	maxSpider := step.ZAPMaxSpiderMinutes
	if maxSpider <= 0 {
		maxSpider = 5
	}
	passiveSec := step.ZAPPassiveWaitSeconds
	if passiveSec <= 0 {
		passiveSec = 60
	}
	passiveMin := (passiveSec + 59) / 60
	if passiveMin < 1 {
		passiveMin = 1
	}
	// Only use page-like URLs as spider seeds. Static assets (JS bundles, JSON, images) as
	// seeds result in spider instances that exit in <1 second and waste concurrency budget.
	pageSeeds := filterPageSeeds(seedURLs)
	browser := strings.TrimSpace(step.ZAPAjaxBrowserID)
	if browser == "" {
		browser = "firefox-headless"
	}
	return zapJobPlan{
		pageSeeds: pageSeeds,
		// primary is the canonical entry-point URL used for scope fallback and the
		// activeScan target — the first page-like seed so a JS file is never targeted.
		primary:    pageSeeds[0],
		step:       step,
		maxSpider:  maxSpider,
		passiveMin: passiveMin,
		browser:    browser,
		useTrad:    step.ZAPSpiderTraditional || !step.ZAPSpiderAjax,
		useAjax:    step.ZAPSpiderAjax,
		reportDir:  reportDir,
		sqlProbes:  sqlProbes,
	}
}

// buildJobs assembles the ordered ZAP automation job list.
func (p zapJobPlan) buildJobs(authHeaders map[string]string) []map[string]any {
	jobs := make([]map[string]any, 0, 16)
	if rj := buildReplacerJobFromAuthHeaders(authHeaders); rj != nil {
		jobs = append(jobs, rj)
	}
	if p.useTrad {
		for _, seed := range p.pageSeeds {
			jobs = append(jobs, map[string]any{
				"type": "spider",
				"parameters": map[string]any{
					"context":     dastContextName,
					"url":         seed,
					"maxDuration": p.maxSpider,
				},
			})
		}
	}
	jobs = append(jobs, p.passiveWaitJob())
	if p.useAjax {
		jobs = append(jobs, p.ajaxJobs()...)
		jobs = append(jobs, p.passiveWaitJob())
	}
	if len(p.sqlProbes) > 0 {
		jobs = append(jobs, map[string]any{
			"type":       "requestor",
			"parameters": map[string]any{},
			"requests":   p.sqlProbes,
		})
	}
	if zapActiveScanEnabled() {
		jobs = append(jobs, p.activeScanJob(), p.passiveWaitJob())
	}
	// Export after requestor/active scan so the saved site tree matches what ZAP discovered
	// overall, not just the early crawl tree. Payload probes are filtered later.
	jobs = append(jobs, p.exportJob(), p.reportJob())
	return jobs
}

func (p zapJobPlan) passiveWaitJob() map[string]any {
	return map[string]any{
		"type":       "passiveScan-wait",
		"parameters": map[string]any{"maxDuration": p.passiveMin},
	}
}

func (p zapJobPlan) ajaxJobs() []map[string]any {
	out := make([]map[string]any, 0, len(p.pageSeeds))
	for _, seed := range p.pageSeeds {
		ajaxParams := map[string]any{
			"context":         dastContextName,
			"url":             seed,
			"maxDuration":     p.maxSpider,
			"browserId":       p.browser,
			"runOnlyIfModern": false,
			"inScopeOnly":     true,
		}
		if p.step.ZAPAjaxEventWait > 0 {
			ajaxParams["eventWait"] = p.step.ZAPAjaxEventWait
		}
		if p.step.ZAPAjaxReloadWait > 0 {
			ajaxParams["reloadWait"] = p.step.ZAPAjaxReloadWait
		}
		if p.step.ZAPAjaxMaxCrawlStates > 0 {
			ajaxParams["maxCrawlStates"] = p.step.ZAPAjaxMaxCrawlStates
		}
		out = append(out, map[string]any{
			"type":       "spiderAjax",
			"parameters": ajaxParams,
		})
	}
	return out
}

func (p zapJobPlan) activeScanJob() map[string]any {
	return map[string]any{
		"type": "activeScan",
		"parameters": map[string]any{
			"context":               dastContextName,
			"url":                   p.primary,
			"maxScanDurationInMins": zapActiveScanMaxMinutes(),
		},
	}
}

func (p zapJobPlan) exportJob() map[string]any {
	return map[string]any{
		"type": "export",
		"parameters": map[string]any{
			"context":   dastContextName,
			"type":      "url",
			"source":    "all",
			"reportDir": p.reportDir,
			"fileName":  urlsExportFileName,
		},
	}
}

func (p zapJobPlan) reportJob() map[string]any {
	return map[string]any{
		"type": "report",
		"parameters": map[string]any{
			"template":      "traditional-json",
			"reportDir":     p.reportDir,
			"reportFile":    reportFileName,
			"reportTitle":   "DAST orchestrator",
			"displayReport": false,
		},
	}
}

// buildIncludePaths returns the trimmed allow-list, falling back to the primary
// URL subtree when no rules are configured.
func buildIncludePaths(allow []string, primary string) []string {
	include := make([]string, 0, len(allow)+1)
	for _, a := range allow {
		if a = strings.TrimSpace(a); a != "" {
			include = append(include, a)
		}
	}
	if len(include) == 0 {
		include = append(include, strings.TrimSuffix(primary, "/")+"/.*")
	}
	return include
}

func zapActiveScanEnabled() bool {
	return strings.TrimSpace(os.Getenv("DAST_ZAP_ACTIVE_SCAN")) != "0"
}

func zapActiveScanMaxMinutes() int {
	if v := strings.TrimSpace(os.Getenv("DAST_ZAP_ACTIVE_SCAN_MAX_MINUTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 10
}

func remapLocalhostForZAPDocker(targetURL string, allow []string) (string, []string, []string) {
	if strings.TrimSpace(os.Getenv("DAST_ZAP_NO_LOCALHOST_REMAP")) == "1" {
		return targetURL, allow, nil
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Hostname() == "" {
		return targetURL, allow, nil
	}
	h := u.Hostname()
	if h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return targetURL, allow, nil
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	u.Host = "host.docker.internal:" + port
	newURL := u.String()
	newAllow := make([]string, len(allow))
	for i, a := range allow {
		a2 := strings.ReplaceAll(a, `127\.0\.0\.1`, `host\.docker\.internal`)
		a2 = strings.ReplaceAll(a2, `localhost`, `host\.docker\.internal`)
		newAllow[i] = a2
	}
	return newURL, newAllow, []string{"--add-host=host.docker.internal:host-gateway"}
}

func runZAPAutorun(outDir, dockerImage string, local bool, dockerExtra []string) error {
	autoInContainer := "/zap/wrk/" + automationFilename
	if local {
		zapSh := strings.TrimSpace(os.Getenv("DAST_ZAP_SH"))
		if zapSh == "" {
			var err error
			zapSh, err = exec.LookPath("zap.sh")
			if err != nil {
				return fmt.Errorf("DAST_ZAP_LOCAL=1: не найден zap.sh (укажите DAST_ZAP_SH): %w", err)
			}
		}
		autoHost := filepath.Join(outDir, automationFilename)
		// Use the outDir itself as ZAP home so ZAP writes its own log files (zap.log) next to
		// the report and export artifacts. Avoid the nested .ZAP_D path: the extra
		// "-config dirs.home=..." flag was redundant with "-dir" and caused ZAP to ignore -dir.
		zapHome := filepath.Join(outDir, ".zap-home")
		if err := os.MkdirAll(zapHome, 0o755); err != nil {
			return fmt.Errorf("zap local home dir: %w", err)
		}
		port := pickFreeTCPPort()
		cmd := exec.Command(
			zapSh,
			"-cmd",
			"-port", strconv.Itoa(port),
			"-dir", zapHome,
			"-autorun", autoHost,
		)
		cmd.Dir = outDir
		cmd.Env = append(os.Environ(),
			"HOME="+zapHome,
			"ZAP_HOME="+zapHome,
		)
		out, err := cmd.CombinedOutput()
		// Always write the log regardless of success/failure so the output is inspectable.
		if len(out) > 0 {
			_ = os.WriteFile(filepath.Join(outDir, autorunLogFileName), out, 0o644)
		} else {
			// ZAP may write its own log to -dir; create a stub so the absence is obvious.
			_ = os.WriteFile(filepath.Join(outDir, autorunLogFileName), []byte("(no stdout captured — see .zap-home/zap.log)\n"), 0o644)
		}
		if err != nil {
			return fmt.Errorf("zap local: %w\n%s", err, string(out))
		}
		return nil
	}

	hostVol, err := absDockerBind(outDir)
	if err != nil {
		return fmt.Errorf("zap docker host path: %w", err)
	}
	args := []string{"run", "--rm"}
	args = append(args, dockerExtra...)
	if extra := strings.Fields(os.Getenv("DAST_ZAP_DOCKER_EXTRA")); len(extra) > 0 {
		args = append(args, extra...)
	}
	args = append(args,
		"-v", hostVol+":/zap/wrk:rw",
		dockerImage,
		"zap.sh", "-cmd", "-autorun", autoInContainer,
	)
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(outDir, autorunLogFileName), out, 0o644)
	if err != nil {
		return fmt.Errorf("zap docker automation: %w\n%s", err, string(out))
	}
	return nil
}

func pickFreeTCPPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 9090
	}
	defer ln.Close()
	if addr, ok := ln.Addr().(*net.TCPAddr); ok && addr.Port > 0 {
		return addr.Port
	}
	return 9090
}
