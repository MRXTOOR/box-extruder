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

// RelativeArtifactsDir — каталог относительно корня job.
const RelativeArtifactsDir = "artifacts/payloads"

// SQLiFileName имя файла с SQLi-пейлоадами в job.
const SQLiFileName = "sqli.txt"

// SQLiEnabled отключает использование пейлоадов: DAST_SQLI_PAYLOADS=0.
func SQLiEnabled() bool {
	return strings.TrimSpace(os.Getenv("DAST_SQLI_PAYLOADS")) != "0"
}

// SQLiPath — абсолютный путь к sqli.txt в job.
func SQLiPath(jobRoot string) string {
	return filepath.Join(jobRoot, RelativeArtifactsDir, SQLiFileName)
}

// WriteSQLi копирует встроенный список в jobRoot/artifacts/payloads/sqli.txt.
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

// LoadLines читает непустые строки (trimmed), пропускает пустые и комментарии #.
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

// KatanaSeedMax лимит дополнительных seed-URL с пейлоадом для Katana (DAST_KATANA_SQLI_SEED_MAX, по умолчанию 200).
func KatanaSeedMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_KATANA_SQLI_SEED_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 200
}

// NucleiBuiltinMax лимит строк пейлоадов во встроенном движке Nuclei (DAST_NUCLEI_SQLI_MAX, по умолчанию 200).
func NucleiBuiltinMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_NUCLEI_SQLI_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 200
}

// ZAPProbeMax лимит GET-проб в ZAP requestor (DAST_ZAP_SQLI_PROBE_MAX, по умолчанию 200).
func ZAPProbeMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_ZAP_SQLI_PROBE_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 200
}

// AppendSQLiSeedURLs добавляет к seeds URL вида base?q=<payload> для обхода с разными query (Katana).
func AppendSQLiSeedURLs(seeds []string, baseURL, paramName, payloadPath string) ([]string, error) {
	max := KatanaSeedMax()
	if max == 0 {
		return seeds, nil
	}
	return AppendQueryParamSeedURLs(seeds, baseURL, paramName, payloadPath, max)
}

// WriteNucleiCLITemplate пишет шаблон для официального nuclei CLI (параметр q, sqli.txt).
func WriteNucleiCLITemplate(sqliFileAbs, outYamlPath string) error {
	return WriteNucleiCLITemplateForFile(sqliFileAbs, outYamlPath, "dast-sqli-payload-probes", "q", SQLiFileName, "SQLi", "sqli,dast")
}

// WriteNucleiXSSCLITemplate — то же для XSS (параметр x, xss.txt).
func WriteNucleiXSSCLITemplate(xssFileAbs, outYamlPath string) error {
	return WriteNucleiCLITemplateForFile(xssFileAbs, outYamlPath, "dast-xss-payload-probes", "x", XSSFileName, "XSS", "xss,dast")
}

// WriteNucleiCLITemplateForFile генерирует YAML для nuclei CLI с заданным query-параметром.
func WriteNucleiCLITemplateForFile(payloadFileAbs, outYamlPath, id, param, fileName, label, tags string) error {
	payloadFileAbs = filepath.Clean(payloadFileAbs)
	tpl := `# Автогенерация: ` + label + `-пейлоады из ` + fileName + `
id: ` + id + `
info:
  name: ` + label + ` payload probes (custom file)
  severity: info
  description: GET с параметром ` + param + ` и строками из ` + fileName + `
  tags: ` + tags + `
http:
  - method: GET
    path:
      - "{{BaseURL}}?` + param + `={{urlencode(payload)}}"
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
