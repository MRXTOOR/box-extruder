package zap

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/google/uuid"
)

// ZAPTraditionalReport is a subset of ZAP JSON report format.
// ZAP 2.12+ часто кладёт URL в alerts[].instances[].uri; старый формат — alerts[].url.
type ZAPTraditionalReport struct {
	Site []struct {
		Name string `json:"@name"`
		Alerts []struct {
			PluginID   string `json:"pluginid"`
			Alert      string `json:"alert"`
			Name       string `json:"name"`
			RiskDesc   string `json:"riskdesc"`
			RiskCode   string `json:"riskcode"`
			Confidence string `json:"confidence"`
			URL        string `json:"url"`
			Method     string `json:"method"`
			Param      string `json:"param"`
			Evidence   string `json:"evidence"`
			Solution   string `json:"solution"`
			Instances  []struct {
				URI      string `json:"uri"`
				Method   string `json:"method"`
				Param    string `json:"param"`
				Evidence string `json:"evidence"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// RunBaseline executes ZAP baseline inside Docker when docker is available.
func RunBaseline(targetURL, outDir, dockerImage string, headerEnv map[string]string) ([]model.Finding, []model.Evidence, error) {
	if dockerImage == "" {
		dockerImage = "ghcr.io/zaproxy/zaproxy:stable"
	}
	if img := os.Getenv("DAST_ZAP_DOCKER_IMAGE"); img != "" {
		dockerImage = img
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, nil, err
	}
	hostVol, err := absDockerBind(outDir)
	if err != nil {
		return nil, nil, fmt.Errorf("zap baseline host path: %w", err)
	}
	reportPath := filepath.Join(outDir, "zap-report.json")
	args := []string{
		"run", "--rm",
		"-v", hostVol + ":/zap/wrk/:rw",
		dockerImage,
		"zap-baseline.py",
		"-t", targetURL,
		"-J", "/zap/wrk/zap-report.json",
		"-I",
	}
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	for k, v := range headerEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	// baseline returns non-zero if alerts found — still parse JSON if present
	_ = out
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		if err != nil {
			return nil, nil, fmt.Errorf("zap baseline: %w\n%s", err, string(out))
		}
		return nil, nil, fmt.Errorf("zap report not written: %w", readErr)
	}
	return ParseReportJSON(data)
}

// ParseReportJSON converts ZAP traditional JSON to unified findings + minimal HTTP evidence.
func ParseReportJSON(data []byte) ([]model.Finding, []model.Evidence, error) {
	var rep ZAPTraditionalReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, nil, fmt.Errorf("zap json: %w", err)
	}
	var findings []model.Finding
	var evidence []model.Evidence
	now := time.Now().UTC()
	dedupe := config.DedupeConfig{LocationKey: "endpoint+method+paramsNormalized", ParamNormalization: "basic"}
	for _, site := range rep.Site {
		siteRoot := strings.TrimSpace(site.Name)
		for _, a := range site.Alerts {
			conf := 0.7
			if c, err := strconv.ParseFloat(a.Confidence, 64); err == nil {
				conf = c / 100.0
			}
			ruleID := a.PluginID
			if ruleID == "" {
				ruleID = strings.ReplaceAll(strings.ToLower(a.Alert), " ", "-")
			}
			emit := func(rawURL, method, param, evText string) {
				method = strings.ToUpper(strings.TrimSpace(method))
				if method == "" {
					method = "GET"
				}
				rawURL = strings.TrimSpace(rawURL)
				if rawURL == "" {
					rawURL = siteRoot
				}
				locKey := noise.BuildLocationKeyFromHTTP(dedupe, method, rawURL)
				if param != "" {
					locKey = locKey + "#param=" + param
				}
				evID := uuid.NewString()
				f := model.Finding{
					FindingID:       uuid.NewString(),
					RuleID:          ruleID,
					Category:        mapRiskToCategory(a.RiskCode, a.RiskDesc),
					Severity:        mapRiskCodeToSeverity(a.RiskCode, a.RiskDesc),
					Confidence:      conf,
					LocationKey:     locKey,
					LifecycleStatus: model.LifecycleDetected,
					FirstSeenAt:     now,
					LastSeenAt:      now,
					EvidenceRefs:    []string{evID},
					Title:           firstNonEmpty(a.Alert, a.Name),
					Description:     a.Solution,
				}
				ev := model.Evidence{
					EvidenceID: evID,
					Type:       model.EvidenceHTTPRequestResponse,
					StepType:   model.StepPassive,
					ContextID:  "",
					Payload: model.HTTPRequestResponsePayload{
						Method:              method,
						URL:                 rawURL,
						StatusCode:          0,
						ResponseBodySnippet: truncate(evText, 2000),
					},
				}
				findings = append(findings, f)
				evidence = append(evidence, ev)
			}
			if len(a.Instances) > 0 {
				for _, inst := range a.Instances {
					emit(inst.URI, inst.Method, inst.Param, inst.Evidence)
				}
			} else {
				emit(a.URL, a.Method, a.Param, a.Evidence)
			}
		}
	}
	return findings, evidence, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func mapRiskToCategory(code, desc string) string {
	if desc != "" {
		return desc
	}
	return "zap-" + code
}

func mapRiskCodeToSeverity(code, desc string) model.Severity {
	c := strings.TrimSpace(code)
	switch c {
	case "3":
		return model.SeverityHigh
	case "2":
		return model.SeverityMedium
	case "1":
		return model.SeverityLow
	case "0":
		return model.SeverityInfo
	}
	d := strings.ToLower(desc)
	if strings.Contains(d, "high") {
		return model.SeverityHigh
	}
	if strings.Contains(d, "medium") {
		return model.SeverityMedium
	}
	if strings.Contains(d, "low") {
		return model.SeverityLow
	}
	return model.SeverityMedium
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// absDockerBind возвращает абсолютный путь для docker -v: относительные пути иначе часто воспринимаются как имена volume.
func absDockerBind(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}
