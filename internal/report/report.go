package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func escapeMarkdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func formatEvidenceMarkdown(ev model.Evidence) string {
	switch ev.Type {
	case model.EvidenceHTTPRequestResponse:
		return formatHTTPRequestResponseEvidence(ev)
	case model.EvidenceAuthVerification:
		return formatAuthVerificationEvidence(ev)
	case model.EvidencePageMarker, model.EvidenceTrace, model.EvidenceOther:
		return formatGenericJSONPayload(ev)
	default:
		return formatGenericJSONPayload(ev)
	}
}

func formatHTTPRequestResponseEvidence(ev model.Evidence) string {
	p, ok := normalizeHTTPPayload(ev.Payload)
	if !ok {
		return formatGenericJSONPayload(ev)
	}
	var b strings.Builder
	if p.Method != "" || p.URL != "" {
		fmt.Fprintf(&b, "- **Request**: `%s` %s\n", p.Method, p.URL)
	}
	if p.StatusCode != 0 {
		fmt.Fprintf(&b, "- **Status**: %d\n", p.StatusCode)
	}
	if len(p.RequestHeaders) > 0 {
		b.WriteString("- **Request headers**:\n\n")
		b.WriteString(formatHeadersBlock(p.RequestHeaders))
		b.WriteString("\n")
	}
	if strings.TrimSpace(p.RequestBody) != "" {
		b.WriteString("- **Request body**:\n\n")
		b.WriteString(fencedCodeBlock(p.RequestBody))
		b.WriteString("\n")
	}
	if len(p.ResponseHeaders) > 0 {
		b.WriteString("- **Response headers**:\n\n")
		b.WriteString(formatHeadersBlock(p.ResponseHeaders))
		b.WriteString("\n")
	}
	if strings.TrimSpace(p.ResponseBodySnippet) != "" {
		b.WriteString("- **Response body (snippet)**:\n\n")
		b.WriteString(fencedCodeBlock(p.ResponseBodySnippet))
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return formatGenericJSONPayload(ev)
	}
	if ev.ContextID != "" {
		fmt.Fprintf(&b, "- **contextId**: %s\n", ev.ContextID)
	}
	return strings.TrimRight(b.String(), "\n")
}

func httpPayloadNonEmpty(p model.HTTPRequestResponsePayload) bool {
	return p.Method != "" || p.URL != "" || p.StatusCode != 0 ||
		len(p.RequestHeaders) > 0 || len(p.ResponseHeaders) > 0 ||
		strings.TrimSpace(p.RequestBody) != "" || strings.TrimSpace(p.ResponseBodySnippet) != ""
}

func normalizeHTTPPayload(payload any) (model.HTTPRequestResponsePayload, bool) {
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

func formatHeadersBlock(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  - `%s`: %s\n", k, h[k])
	}
	return b.String()
}

func fencedCodeBlock(s string) string {
	s = strings.TrimRight(s, "\n")
	return "```\n" + s + "\n```\n"
}

func formatAuthVerificationEvidence(ev model.Evidence) string {
	switch p := ev.Payload.(type) {
	case map[string]any:
		var b strings.Builder
		if v, ok := p["providerId"]; ok {
			fmt.Fprintf(&b, "- **providerId**: %v\n", v)
		}
		if v, ok := p["checkUrl"]; ok {
			fmt.Fprintf(&b, "- **checkUrl**: %v\n", v)
		}
		if v, ok := p["expectedStatus"]; ok {
			fmt.Fprintf(&b, "- **expectedStatus**: %v\n", v)
		}
		if v, ok := p["actualStatus"]; ok {
			fmt.Fprintf(&b, "- **actualStatus**: %v\n", v)
		}
		if v, ok := p["result"]; ok {
			fmt.Fprintf(&b, "- **result**: %v\n", v)
		}
		if v, ok := p["detail"]; ok && fmt.Sprintf("%v", v) != "" {
			fmt.Fprintf(&b, "- **detail**: %v\n", v)
		}
		if ev.ContextID != "" {
			fmt.Fprintf(&b, "- **contextId**: %s\n", ev.ContextID)
		}
		return strings.TrimRight(b.String(), "\n")
	case model.AuthVerificationPayload:
		var b strings.Builder
		fmt.Fprintf(&b, "- **providerId**: %s\n", p.ProviderID)
		if p.CheckURL != "" {
			fmt.Fprintf(&b, "- **checkUrl**: %s\n", p.CheckURL)
		}
		if p.ExpectedStatus != 0 {
			fmt.Fprintf(&b, "- **expectedStatus**: %d\n", p.ExpectedStatus)
		}
		if p.ActualStatus != 0 {
			fmt.Fprintf(&b, "- **actualStatus**: %d\n", p.ActualStatus)
		}
		fmt.Fprintf(&b, "- **result**: %s\n", p.Result)
		if p.Detail != "" {
			fmt.Fprintf(&b, "- **detail**: %s\n", p.Detail)
		}
		if ev.ContextID != "" {
			fmt.Fprintf(&b, "- **contextId**: %s\n", ev.ContextID)
		}
		return strings.TrimRight(b.String(), "\n")
	default:
		return formatGenericJSONPayload(ev)
	}
}

func formatGenericJSONPayload(ev model.Evidence) string {
	raw, err := json.MarshalIndent(ev.Payload, "", "  ")
	if err != nil {
		return fmt.Sprintf("```\n%v\n```\n", ev.Payload)
	}
	return "```json\n" + string(raw) + "\n```\n"
}

// RenderMarkdown builds report.md content from job and findings (final).
// evidenceThreshold — budgets.verification.evidenceThreshold для колонки «Evidence quality»; пусто = low.
// reportUpdatedAt — если не nil, в шапку добавляется строка о времени последнего обновления отчёта.
// scannedEndpoints — список просканированных эндпоинтов (из katana/zap).
func RenderMarkdown(jobName, baseURL, preset string, started, finished time.Time, findings []model.Finding, evidence map[string]model.Evidence, includeEvidence bool, evidenceThreshold string, reportUpdatedAt *time.Time, scannedEndpoints []string) []byte {
	var b bytes.Buffer

	fmt.Fprintf(&b, "# DAST Security Report\n\n")
	fmt.Fprintf(&b, "| | |\n")
	fmt.Fprintf(&b, "|---|---|\n")
	fmt.Fprintf(&b, "| **Сканирование** | %s |\n", jobName)
	fmt.Fprintf(&b, "| **Цель** | %s |\n", baseURL)
	fmt.Fprintf(&b, "| **Начало** | %s |\n", started.UTC().Format("02.01.2006 15:04:05 MST"))
	fmt.Fprintf(&b, "| **Завершение** | %s |\n", finished.UTC().Format("02.01.2006 15:04:05 MST"))
	fmt.Fprintf(&b, "\n---\n\n")

	fmt.Fprintf(&b, "## Executive Summary\n\n")

	var confirmed, unconf, suppressed int
	bySev := map[model.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
		switch f.LifecycleStatus {
		case model.LifecycleConfirmed:
			confirmed++
		case model.LifecycleUnconfirmed, model.LifecycleDetected:
			unconf++
		case model.LifecycleFalsePositiveSuppressed:
			suppressed++
		}
	}

	fmt.Fprintf(&b, "| Статус | Количество |\n")
	fmt.Fprintf(&b, "|--------|-----------|\n")
	fmt.Fprintf(&b, "| Подтвержденные | %d |\n", confirmed)
	fmt.Fprintf(&b, "| Обнаруженные | %d |\n", unconf)
	fmt.Fprintf(&b, "| Подавленные | %d |\n", suppressed)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "### Raspredelenie po severity\n\n")
	fmt.Fprintf(&b, "| Uroven | Kol-vo | Opisanie |\n")
	fmt.Fprintf(&b, "|---------|--------|----------|\n")
	fmt.Fprintf(&b, "| CRITICAL | %d | Kriticheskaya uyazvimost |\n", bySev[model.SeverityCritical])
	fmt.Fprintf(&b, "| HIGH | %d | Vysokaya seryoznost |\n", bySev[model.SeverityHigh])
	fmt.Fprintf(&b, "| MEDIUM | %d | Srednyaya seryoznost |\n", bySev[model.SeverityMedium])
	fmt.Fprintf(&b, "| LOW | %d | Nizkaya seryoznost |\n", bySev[model.SeverityLow])
	fmt.Fprintf(&b, "| INFO | %d | Informaciya |\n", bySev[model.SeverityInfo])
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## Findings\n\n")

	severities := []struct {
		sev   model.Severity
		title string
	}{
		{model.SeverityCritical, "CRITICAL"},
		{model.SeverityHigh, "HIGH"},
		{model.SeverityMedium, "MEDIUM"},
		{model.SeverityLow, "LOW"},
		{model.SeverityInfo, "INFO"},
	}

	for _, sev := range severities {
		var sevFindings []model.Finding
		for _, f := range findings {
			if f.Severity == sev.sev {
				sevFindings = append(sevFindings, f)
			}
		}
		if len(sevFindings) == 0 {
			continue
		}

		fmt.Fprintf(&b, "### %s (%d)\n\n", sev.title, len(sevFindings))
		fmt.Fprintf(&b, "| # | Rule | Status | Location | Title |\n")
		fmt.Fprintf(&b, "|---|------|--------|---------|-------|\n")
		for i, f := range sevFindings {
			title := escapeMarkdownCell(f.Title)
			location := escapeMarkdownCell(f.LocationKey)
			status := statusLabel(f.LifecycleStatus)
			fmt.Fprintf(&b, "| %d | `%s` | %s | `%s` | %s |\n", i+1, f.RuleID, status, location, title)
		}
		fmt.Fprintf(&b, "\n")
	}

	if includeEvidence && len(findings) > 0 {
		fmt.Fprintf(&b, "---\n\n## Evidence\n\n")
		for _, sev := range severities {
			var printedSevHeader bool
			for _, f := range findings {
				if f.Severity != sev.sev {
					continue
				}
				for _, eid := range f.EvidenceRefs {
					ev, ok := evidence[eid]
					if !ok {
						continue
					}
					if ev.Type == model.EvidenceManualReview {
						continue
					}
					if !printedSevHeader {
						fmt.Fprintf(&b, "### %s\n\n", sev.title)
						printedSevHeader = true
					}
					title := escapeMarkdownCell(f.Title)
					fmt.Fprintf(&b, "#### %s — `%s`\n\n", title, f.RuleID)
					b.WriteString(formatEvidenceMarkdown(ev))
					b.WriteString("\n")
				}
			}
		}
	}

	return b.Bytes()
}

func statusLabel(status model.LifecycleStatus) string {
	switch status {
	case model.LifecycleConfirmed:
		return "Confirmed"
	case model.LifecycleFalsePositiveSuppressed:
		return "Suppressed"
	case model.LifecycleRecheckRequired:
		return "Recheck Required"
	default:
		return "Detected"
	}
}

// PandocToDocx runs pandoc if available; returns error if pandoc missing.
func PandocToDocx(mdPath, docxPath, referenceDocx string) error {
	args := []string{mdPath, "-o", docxPath}
	if referenceDocx != "" {
		if _, err := exec.LookPath("pandoc"); err != nil {
			return err
		}
		args = append(args, "--reference-doc="+referenceDocx)
	}
	cmd := exec.Command("pandoc", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pandoc: %w: %s", err, string(out))
	}
	return nil
}

// WriteReportHTMLFallback пишет UTF-8 HTML с тем же содержимым, что report.md (в <pre>), чтобы открыть
// отчёт в Word / LibreOffice без pandoc. Путь: рядом с report.docx, имя report.html.
func WriteReportHTMLFallback(mdPath, htmlPath string) error {
	raw, err := os.ReadFile(mdPath)
	if err != nil {
		return err
	}
	escaped := html.EscapeString(string(raw))
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<title>DAST Report</title>\n")
	b.WriteString("<style>body{font-family:system-ui,Segoe UI,sans-serif;margin:1rem}pre{white-space:pre-wrap;word-wrap:break-word;font-size:14px}</style>\n")
	b.WriteString("</head>\n<body>\n<pre>")
	b.WriteString(escaped)
	b.WriteString("</pre>\n</body>\n</html>\n")
	return os.WriteFile(htmlPath, []byte(b.String()), 0o644)
}

// PandocToDocxOptional: при наличии pandoc — report.docx; иначе — report.html (fallback для Word/LibreOffice).
func PandocToDocxOptional(mdPath, docxPath, referenceDocx string) error {
	if _, err := exec.LookPath("pandoc"); err != nil {
		htmlPath := strings.TrimSuffix(docxPath, ".docx") + ".html"
		if err := WriteReportHTMLFallback(mdPath, htmlPath); err != nil {
			stub := []byte("Install pandoc for report.docx; HTML fallback failed: " + err.Error() + "\n")
			return os.WriteFile(docxPath+".txt", stub, 0o644)
		}
		return nil
	}
	return PandocToDocx(mdPath, docxPath, referenceDocx)
}

// ResolveReferenceDoc finds reference docx path from templateRef like template://file.docx
func ResolveReferenceDoc(templateRef, workDir string) string {
	if templateRef == "" {
		return ""
	}
	if strings.HasPrefix(templateRef, "template://") {
		name := strings.TrimPrefix(templateRef, "template://")
		return filepath.Join(workDir, name)
	}
	return templateRef
}
