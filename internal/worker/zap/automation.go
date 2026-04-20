package zap

import (
	"fmt"
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

// RunAutomation runs ZAP via `zap.sh -cmd -autorun` (Docker или локальный ZAP).
// allow — regex из scope.allow; при пустом списке добавляется baseURL.*
// authHeaders — заголовки для всех запросов (Authorization, Cookie и т.д.); попадают в automation как job replacer.
// sqlPayloadPath / xssPayloadPath — sqli.txt и xss.txt для ZAP requestor до spider.
func RunAutomation(
	targetURL, outDir, dockerImage, configFileDir string,
	allow []string,
	step config.ScanStep,
	authHeaders map[string]string,
	sqlPayloadPath, xssPayloadPath string,
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
		var zt string
		var za []string
		zt, za, zapDockerExtra = remapLocalhostForZAPDocker(targetURL, allow)
		probes := BuildMergedPayloadProbes(zt, authHeaders, sqlPayloadPath, xssPayloadPath)
		yamlBytes, err = buildAutomationYAML(zt, za, step, reportDir, authHeaders, probes)
		if err != nil {
			return nil, nil, err
		}
	}

	autoPath := filepath.Join(outDir, automationFilename)
	if err := os.WriteFile(autoPath, yamlBytes, 0o644); err != nil {
		return nil, nil, err
	}

	if err := runZAPAutorun(outDir, dockerImage, useLocalZAP(), zapDockerExtra); err != nil {
		return nil, nil, err
	}

	reportPath := filepath.Join(outDir, reportFileName)
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("zap automation: отчёт не найден %s: %w", reportPath, err)
	}
	return ParseReportJSON(data)
}

func useLocalZAP() bool {
	return strings.TrimSpace(os.Getenv("DAST_ZAP_LOCAL")) == "1"
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
		// Поля по документации ZAP: https://www.zaproxy.org/docs/desktop/addons/replacer/automation/
		rules = append(rules, map[string]any{
			"description":         "DAST auth header " + name,
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

func buildAutomationYAML(targetURL string, allow []string, step config.ScanStep, reportDir string, authHeaders map[string]string, sqlProbes []map[string]any) ([]byte, error) {
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

	include := make([]string, 0, len(allow)+1)
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a != "" {
			include = append(include, a)
		}
	}
	if len(include) == 0 {
		include = append(include, strings.TrimSuffix(targetURL, "/")+"/.*")
	}

	useTrad := step.ZAPSpiderTraditional || !step.ZAPSpiderAjax
	useAjax := step.ZAPSpiderAjax
	browser := strings.TrimSpace(step.ZAPAjaxBrowserID)
	if browser == "" {
		browser = "firefox-headless"
	}

	jobs := make([]map[string]any, 0, 8)
	if rj := buildReplacerJobFromAuthHeaders(authHeaders); rj != nil {
		jobs = append(jobs, rj)
	}
	if len(sqlProbes) > 0 {
		jobs = append(jobs, map[string]any{
			"type":       "requestor",
			"parameters": map[string]any{},
			"requests":   sqlProbes,
		})
	}
	if useTrad {
		jobs = append(jobs, map[string]any{
			"type": "spider",
			"parameters": map[string]any{
				"context":     dastContextName,
				"url":         targetURL,
				"maxDuration": maxSpider,
			},
		})
	}
	jobs = append(jobs, map[string]any{
		"type": "passiveScan-wait",
		"parameters": map[string]any{
			"maxDuration": passiveMin,
		},
	})
	if useAjax {
		jobs = append(jobs, map[string]any{
			"type": "spiderAjax",
			"parameters": map[string]any{
				"context":       dastContextName,
				"url":           targetURL,
				"maxDuration":   maxSpider,
				"browserId":     browser,
				"runOnlyIfModern": false,
				"inScopeOnly":   true,
			},
		})
		jobs = append(jobs, map[string]any{
			"type": "passiveScan-wait",
			"parameters": map[string]any{
				"maxDuration": passiveMin,
			},
		})
	}
	if zapActiveScanEnabled() {
		jobs = append(jobs, map[string]any{
			"type": "activeScan",
			"parameters": map[string]any{
				"context":               dastContextName,
				"url":                   targetURL,
				"maxScanDurationInMins": zapActiveScanMaxMinutes(),
			},
		})
		jobs = append(jobs, map[string]any{
			"type": "passiveScan-wait",
			"parameters": map[string]any{
				"maxDuration": passiveMin,
			},
		})
	}
	jobs = append(jobs, map[string]any{
		"type": "report",
		"parameters": map[string]any{
			"template":    "traditional-json",
			"reportDir":     reportDir,
			"reportFile":    reportFileName,
			"reportTitle":   "DAST orchestrator",
			"displayReport": false,
		},
	})

	doc := map[string]any{
		"env": map[string]any{
			"contexts": []any{
				map[string]any{
					"name":         dastContextName,
					"urls":         []string{targetURL},
					"includePaths": include,
				},
			},
			"parameters": map[string]any{
				"failOnError":        false,
				"failOnWarning":      false,
				"progressToStdout":   true,
			},
		},
		"jobs": jobs,
	}
	return yaml.Marshal(doc)
}

// zapActiveScanEnabled включает activeScan в Automation Framework.
// По умолчанию включено; отключение: DAST_ZAP_ACTIVE_SCAN=0.
func zapActiveScanEnabled() bool {
	return strings.TrimSpace(os.Getenv("DAST_ZAP_ACTIVE_SCAN")) != "0"
}

// zapActiveScanMaxMinutes ограничивает длительность activeScan.
// Значение можно задать через DAST_ZAP_ACTIVE_SCAN_MAX_MINUTES, по умолчанию 10.
func zapActiveScanMaxMinutes() int {
	if v := strings.TrimSpace(os.Getenv("DAST_ZAP_ACTIVE_SCAN_MAX_MINUTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 10
}

// remapLocalhostForZAPDocker переписывает 127.0.0.1/localhost в host.docker.internal для ZAP в Docker:
// из контейнера ZAP localhost — это сам контейнер, а не хост с Juice Shop.
// Добавляет --add-host=host.docker.internal:host-gateway для docker run.
// Отключение: DAST_ZAP_NO_LOCALHOST_REMAP=1 или локальный ZAP (DAST_ZAP_LOCAL=1).
func remapLocalhostForZAPDocker(targetURL string, allow []string) (string, []string, []string) {
	if useLocalZAP() {
		return targetURL, allow, nil
	}
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
		cmd := exec.Command(zapSh, "-cmd", "-autorun", autoHost)
		cmd.Dir = outDir
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
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
	if err != nil {
		return fmt.Errorf("zap docker automation: %w\n%s", err, string(out))
	}
	return nil
}
