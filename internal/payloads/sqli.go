package payloads

import (
	"bufio"
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed sqli.txt
var sqliEmbedded []byte

const RelativeArtifactsDir = "artifacts/payloads"

const SQLiFileName = "sqli.txt"

func SQLiEnabled() bool {
	return strings.TrimSpace(os.Getenv("DAST_SQLI_PAYLOADS")) != "0"
}

func SQLiPath(jobRoot string) string {
	return filepath.Join(jobRoot, RelativeArtifactsDir, SQLiFileName)
}

func WriteSQLi(jobRoot string) (string, error) {
	if !SQLiEnabled() {
		return "", nil
	}
	dir := filepath.Join(jobRoot, RelativeArtifactsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, SQLiFileName)
	if err := os.WriteFile(p, sqliEmbedded, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

func LoadLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func KatanaSeedMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_KATANA_SQLI_SEED_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 200
}

func NucleiBuiltinMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_NUCLEI_SQLI_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 200
}

func ZAPProbeMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_ZAP_SQLI_PROBE_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 200
}

func AppendSQLiSeedURLs(seeds []string, baseURL, paramName, payloadPath string) ([]string, error) {
	max := KatanaSeedMax()
	if max == 0 {
		return seeds, nil
	}
	return AppendQueryParamSeedURLs(seeds, baseURL, paramName, payloadPath, max)
}

func WriteNucleiCLITemplate(sqliFileAbs, outYamlPath string) error {
	return WriteNucleiCLITemplateForFile(sqliFileAbs, outYamlPath, nucleiCLITemplateSpec{
		id: "dast-sqli-payload-probes", param: "q", fileName: SQLiFileName, label: "SQLi", tags: "sqli,dast",
	})
}

func WriteNucleiXSSCLITemplate(xssFileAbs, outYamlPath string) error {
	return WriteNucleiCLITemplateForFile(xssFileAbs, outYamlPath, nucleiCLITemplateSpec{
		id: "dast-xss-payload-probes", param: "x", fileName: XSSFileName, label: "XSS", tags: "xss,dast",
	})
}

// nucleiCLITemplateSpec describes the descriptive fields of a generated Nuclei
// CLI payload template.
type nucleiCLITemplateSpec struct {
	id       string
	param    string
	fileName string
	label    string
	tags     string
}

func WriteNucleiCLITemplateForFile(payloadFileAbs, outYamlPath string, spec nucleiCLITemplateSpec) error {
	payloadFileAbs = filepath.Clean(payloadFileAbs)
	tpl := `# Автогенерация: ` + spec.label + `-пейлоады из ` + spec.fileName + `
id: ` + spec.id + `
info:
  name: ` + spec.label + ` payload probes (custom file)
  severity: info
  description: GET с параметром ` + spec.param + ` и строками из ` + spec.fileName + `
  tags: ` + spec.tags + `
http:
  - method: GET
    path:
      - "{{BaseURL}}?` + spec.param + `={{urlencode(payload)}}"
    payloads:
      payload:
        - ` + payloadFileAbs + `
    matchers:
      - type: status
        status:
          - 200
          - 301
          - 302
          - 400
          - 403
          - 404
          - 500
          - 502
`
	return os.WriteFile(outYamlPath, []byte(tpl), 0o644)
}
