package noise

import (
	"fmt"
	"strings"

	"github.com/box-extruder/dast/internal/model"
)

const (
	minBodyMedium = 8
	minBodyHigh   = 16
)

// HTTPEvidenceMeetsThreshold returns true if HTTP evidence satisfies budgets.verification.evidenceThreshold.
func HTTPEvidenceMeetsThreshold(ev model.Evidence, threshold string) bool {
	if ev.Type != model.EvidenceHTTPRequestResponse {
		return false
	}
	p, ok := extractHTTPPayload(ev.Payload)
	if !ok {
		return false
	}
	th := strings.ToLower(strings.TrimSpace(threshold))
	if th == "" {
		th = "low"
	}
	switch th {
	case "high":
		return meetsHigh(p)
	case "medium":
		return meetsMedium(p)
	default:
		return meetsLow(p)
	}
}

// FindingEvidenceQualityLabel summarizes HTTP evidence for a finding vs threshold: sufficient | partial | non-http | none.
func FindingEvidenceQualityLabel(f model.Finding, evidenceByID map[string]model.Evidence, threshold string) string {
	if len(f.EvidenceRefs) == 0 {
		return "none"
	}
	var hasHTTP, hasSufficient bool
	for _, eid := range f.EvidenceRefs {
		ev, ok := evidenceByID[eid]
		if !ok {
			continue
		}
		if ev.Type != model.EvidenceHTTPRequestResponse {
			continue
		}
		hasHTTP = true
		if HTTPEvidenceMeetsThreshold(ev, threshold) {
			hasSufficient = true
			break
		}
	}
	if hasSufficient {
		return "sufficient"
	}
	if hasHTTP {
		return "partial"
	}
	for _, eid := range f.EvidenceRefs {
		if _, ok := evidenceByID[eid]; ok {
			return "non-http"
		}
	}
	return "none"
}

func meetsLow(p model.HTTPRequestResponsePayload) bool {
	url := strings.TrimSpace(p.URL)
	if url == "" {
		return false
	}
	return true
}

func meetsMedium(p model.HTTPRequestResponsePayload) bool {
	if !meetsLow(p) {
		return false
	}
	if p.StatusCode != 0 {
		return true
	}
	return len(strings.TrimSpace(p.ResponseBodySnippet)) >= minBodyMedium
}

func meetsHigh(p model.HTTPRequestResponsePayload) bool {
	if !meetsLow(p) {
		return false
	}
	if p.StatusCode == 0 {
		return false
	}
	if len(strings.TrimSpace(p.ResponseBodySnippet)) < minBodyHigh {
		return false
	}
	return len(p.ResponseHeaders) > 0 || len(p.RequestHeaders) > 0
}

func extractHTTPPayload(payload any) (model.HTTPRequestResponsePayload, bool) {
	switch p := payload.(type) {
	case model.HTTPRequestResponsePayload:
		if httpPayloadNonEmpty(p) {
			return p, true
		}
		return model.HTTPRequestResponsePayload{}, false
	case map[string]any:
		out := mapToHTTPPayload(p)
		return out, httpPayloadNonEmpty(out)
	default:
		return model.HTTPRequestResponsePayload{}, false
	}
}

func httpPayloadNonEmpty(p model.HTTPRequestResponsePayload) bool {
	return p.Method != "" || p.URL != "" || p.StatusCode != 0 ||
		len(p.RequestHeaders) > 0 || len(p.ResponseHeaders) > 0 ||
		strings.TrimSpace(p.RequestBody) != "" || strings.TrimSpace(p.ResponseBodySnippet) != ""
}

func mapToHTTPPayload(m map[string]any) model.HTTPRequestResponsePayload {
	var out model.HTTPRequestResponsePayload
	if v, ok := m["method"].(string); ok {
		out.Method = v
	}
	if v, ok := m["url"].(string); ok {
		out.URL = v
	}
	out.StatusCode = intFromAny(m["statusCode"])
	if v, ok := m["requestBody"].(string); ok {
		out.RequestBody = v
	}
	if v, ok := m["responseBodySnippet"].(string); ok {
		out.ResponseBodySnippet = v
	}
	out.RequestHeaders = stringMapFromAny(m["requestHeaders"])
	out.ResponseHeaders = stringMapFromAny(m["responseHeaders"])
	return out
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	default:
		return 0
	}
}

func stringMapFromAny(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string)
	for k, val := range m {
		out[k] = fmt.Sprintf("%v", val)
	}
	return out
}
