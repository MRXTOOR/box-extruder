package nuclei

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/box-extruder/dast/internal/payloads"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Template is a Nuclei-like YAML subset.
type Template struct {
	ID          string       `yaml:"id"`
	Name        string       `yaml:"name"`
	Severity    string       `yaml:"severity"`
	Description string       `yaml:"description"`
	HTTP        []HTTPBlock  `yaml:"http"`
}

type HTTPBlock struct {
	Method   string          `yaml:"method"`
	Path     string          `yaml:"path"`
	Matchers []Matcher       `yaml:"matchers"`
	PayloadQueryParam string `yaml:"payloadQueryParam,omitempty"`
	PayloadFile       string `yaml:"payloadFile,omitempty"`
}

type Matcher struct {
	Type  string   `yaml:"type"`
	Part  string   `yaml:"part"`
	Words []string `yaml:"words"`
}

// LoadTemplates loads YAML files from paths (files or directories).
func LoadTemplates(paths []string) ([]Template, error) {
	var all []Template
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if st.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
					continue
				}
				tpls, err := loadFile(filepath.Join(p, e.Name()))
				if err != nil {
					return nil, err
				}
				all = append(all, tpls...)
			}
			continue
		}
		tpls, err := loadFile(p)
		if err != nil {
			return nil, err
		}
		all = append(all, tpls...)
	}
	return all, nil
}

func loadFile(path string) ([]Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if t.ID == "" {
		t.ID = filepath.Base(path)
	}
	return []Template{t}, nil
}

func Run(client *http.Client, bases []string, tpls []Template, ctxID string, dedupe config.DedupeConfig, workDir string) ([]model.Finding, []model.Evidence, error) {
	if client == nil {
		client = &http.Client{Timeout: 25 * time.Second}
	}
	var findings []model.Finding
	var evidence []model.Evidence
	now := time.Now().UTC()
	for _, base := range bases {
		base = strings.TrimRight(base, "/")
		for _, tpl := range tpls {
			for _, block := range tpl.HTTP {
				method := strings.ToUpper(strings.TrimSpace(block.Method))
				if method == "" {
					method = "GET"
				}
				if block.PayloadQueryParam != "" && block.PayloadFile != "" {
					p := block.PayloadFile
					if !filepath.IsAbs(p) && workDir != "" {
						p = filepath.Join(workDir, p)
					}
					baseName := strings.ToLower(filepath.Base(p))
					var enabled bool
					var max int
					switch {
					case baseName == strings.ToLower(payloads.SQLiFileName) && payloads.SQLiEnabled():
						enabled = true
						max = payloads.NucleiBuiltinMax()
					case baseName == strings.ToLower(payloads.XSSFileName) && payloads.XSSEnabled():
						enabled = true
						max = payloads.NucleiXSSBuiltinMax()
					}
					if !enabled {
						continue
					}
					lines, err := payloads.LoadLines(p)
					if err != nil {
						continue
					}
					for i, line := range lines {
						if i >= max {
							break
						}
						path := block.Path
						if path == "" {
							path = "/"
						}
						if !strings.HasPrefix(path, "/") {
							path = "/" + path
						}
						u, err := url.Parse(base + path)
						if err != nil {
							continue
						}
						q := u.Query()
						q.Set(block.PayloadQueryParam, line)
						u.RawQuery = q.Encode()
						fullURL := u.String()
						f2, e2 := runOneHTTP(client, method, fullURL, block.Matchers, tpl, ctxID, dedupe, now)
						if f2 != nil {
							findings = append(findings, *f2)
							evidence = append(evidence, e2)
						}
					}
					continue
				}
				path := block.Path
				if path == "" {
					path = "/"
				}
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				fullURL := base + path
				f2, e2 := runOneHTTP(client, method, fullURL, block.Matchers, tpl, ctxID, dedupe, now)
				if f2 != nil {
					findings = append(findings, *f2)
					evidence = append(evidence, e2)
				}
			}
		}
	}
	return findings, evidence, nil
}

func runOneHTTP(client *http.Client, method, fullURL string, matchers []Matcher, tpl Template, ctxID string, dedupe config.DedupeConfig, now time.Time) (*model.Finding, model.Evidence) {
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, model.Evidence{}
	}
	resp, err := client.Do(req)
	body := ""
	status := 0
	if resp != nil {
		status = resp.StatusCode
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		body = string(b)
		resp.Body.Close()
	}
	if err != nil {
		return nil, model.Evidence{}
	}
	if !matchAll(matchers, body, status) {
		return nil, model.Evidence{}
	}
	evID := uuid.NewString()
	locKey := noise.BuildLocationKeyFromHTTP(dedupe, method, fullURL)
	sev := parseSeverity(tpl.Severity)
	f := model.Finding{
		FindingID:       uuid.NewString(),
		RuleID:          "nuclei:" + tpl.ID,
		Category:        "template-match",
		Severity:        sev,
		Confidence:      0.85,
		LocationKey:     locKey,
		LifecycleStatus: model.LifecycleDetected,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		EvidenceRefs:    []string{evID},
		Title:           first(tpl.Name, tpl.ID),
		Description:     tpl.Description,
	}
	ev := model.Evidence{
		EvidenceID: evID,
		Type:       model.EvidenceHTTPRequestResponse,
		StepType:   model.StepNucleiTemplates,
		ContextID:  ctxID,
		Payload: model.HTTPRequestResponsePayload{
			Method:              method,
			URL:                 fullURL,
			StatusCode:          status,
			ResponseBodySnippet: truncate(body, 1500),
		},
	}
	return &f, ev
}

func first(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func matchAll(matchers []Matcher, body string, status int) bool {
	if len(matchers) == 0 {
		return false
	}
	for _, m := range matchers {
		part := body
		p := strings.ToLower(strings.TrimSpace(m.Part))
		if p == "status" || p == "" && strings.ToLower(m.Type) == "status" {
			part = fmt.Sprintf("%d", status)
		}
		switch strings.ToLower(m.Type) {
		case "word":
			ok := false
			for _, w := range m.Words {
				if strings.Contains(part, w) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func parseSeverity(s string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium", "med":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
