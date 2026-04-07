package zap

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/box-extruder/dast/internal/payloads"
)

// BuildQueryParamRequestorProbes — GET ?param=payload для ZAP requestor.
func BuildQueryParamRequestorProbes(baseURL string, authHeaders map[string]string, payloadPath, param, namePrefix string, max int) []map[string]any {
	if payloadPath == "" || max <= 0 {
		return nil
	}
	lines, err := payloads.LoadLines(payloadPath)
	if err != nil {
		return nil
	}
	uBase, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || uBase.Scheme == "" || uBase.Host == "" {
		return nil
	}
	names := make([]string, 0, len(authHeaders))
	for k := range authHeaders {
		names = append(names, k)
	}
	sort.Strings(names)
	var hdrs []string
	for _, k := range names {
		hdrs = append(hdrs, fmt.Sprintf("%s: %s", k, authHeaders[k]))
	}
	p := strings.TrimSpace(param)
	if p == "" {
		p = "q"
	}
	prefix := strings.TrimSpace(namePrefix)
	if prefix == "" {
		prefix = "probe"
	}
	var reqs []map[string]any
	for i, line := range lines {
		if i >= max {
			break
		}
		u := *uBase
		q := u.Query()
		q.Set(p, line)
		u.RawQuery = q.Encode()
		m := map[string]any{
			"url":    u.String(),
			"method": "GET",
			"name":   fmt.Sprintf("%s-%d", prefix, i+1),
		}
		if len(hdrs) > 0 {
			m["headers"] = hdrs
		}
		reqs = append(reqs, m)
	}
	return reqs
}

// BuildMergedPayloadProbes объединяет SQLi (?q=) и XSS (?x=) при включённых флагах.
func BuildMergedPayloadProbes(baseURL string, authHeaders map[string]string, sqlPath, xssPath string) []map[string]any {
	var out []map[string]any
	if payloads.SQLiEnabled() && sqlPath != "" {
		out = append(out, BuildQueryParamRequestorProbes(baseURL, authHeaders, sqlPath, "q", "sqli", payloads.ZAPProbeMax())...)
	}
	if payloads.XSSEnabled() && xssPath != "" {
		out = append(out, BuildQueryParamRequestorProbes(baseURL, authHeaders, xssPath, "x", "xss", payloads.ZAPXSSProbeMax())...)
	}
	return out
}
