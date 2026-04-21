package payloads

import (
	_ "embed"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var xssEmbedded []byte

const XSSFileName = "xss.txt"

func XSSEnabled() bool {
	return strings.TrimSpace(os.Getenv("DAST_XSS_PAYLOADS")) != "0"
}

func XSSPath(jobRoot string) string {
	return filepath.Join(jobRoot, RelativeArtifactsDir, XSSFileName)
}

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

func WritePayloads(jobRoot string) error {
	if _, err := WriteSQLi(jobRoot); err != nil {
		return err
	}
	_, err := WriteXSS(jobRoot)
	return err
}

func KatanaXSSSeedMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_KATANA_XSS_SEED_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 450
}

func NucleiXSSBuiltinMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_NUCLEI_XSS_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 450
}

func ZAPXSSProbeMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_ZAP_XSS_PROBE_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 300
}

func AppendXSSSeedURLs(seeds []string, baseURL, paramName, payloadPath string) ([]string, error) {
	return AppendQueryParamSeedURLs(seeds, baseURL, paramName, payloadPath, KatanaXSSSeedMax())
}
