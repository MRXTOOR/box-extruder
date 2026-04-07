package payloads

import (
	_ "embed"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed xss.txt
var xssEmbedded []byte

// XSSFileName — имя файла с XSS-пейлоадами в job.
const XSSFileName = "xss.txt"

// XSSEnabled отключает XSS-пейлоады: DAST_XSS_PAYLOADS=0.
func XSSEnabled() bool {
	return strings.TrimSpace(os.Getenv("DAST_XSS_PAYLOADS")) != "0"
}

// XSSPath — абсолютный путь к xss.txt в job.
func XSSPath(jobRoot string) string {
	return filepath.Join(jobRoot, RelativeArtifactsDir, XSSFileName)
}

// WriteXSS копирует встроенный список в jobRoot/artifacts/payloads/xss.txt.
func WriteXSS(jobRoot string) (string, error) {
	if !XSSEnabled() {
		return "", nil
	}
	dir := filepath.Join(jobRoot, RelativeArtifactsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, XSSFileName)
	if err := os.WriteFile(p, xssEmbedded, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// WritePayloads пишет sqli.txt и xss.txt в артефакты job.
func WritePayloads(jobRoot string) error {
	if _, err := WriteSQLi(jobRoot); err != nil {
		return err
	}
	_, err := WriteXSS(jobRoot)
	return err
}

// KatanaXSSSeedMax — лимит seed-URL с параметром x= (DAST_KATANA_XSS_SEED_MAX, по умолчанию 450).
func KatanaXSSSeedMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_KATANA_XSS_SEED_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 450
}

// NucleiXSSBuiltinMax — лимит строк xss.txt во встроенном Nuclei (DAST_NUCLEI_XSS_MAX, по умолчанию 450).
func NucleiXSSBuiltinMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_NUCLEI_XSS_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 450
}

// ZAPXSSProbeMax — лимит GET-проб ZAP для x= (DAST_ZAP_XSS_PROBE_MAX, по умолчанию 300).
func ZAPXSSProbeMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_ZAP_XSS_PROBE_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 300
}

// AppendXSSSeedURLs добавляет к seeds URL вида base?x=<payload> (Katana).
func AppendXSSSeedURLs(seeds []string, baseURL, paramName, payloadPath string) ([]string, error) {
	return AppendQueryParamSeedURLs(seeds, baseURL, paramName, payloadPath, KatanaXSSSeedMax())
}
