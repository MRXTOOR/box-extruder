package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
)

func escapeMarkdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// reviewMarkdownCell — ячейка ручного review; пусто → «—», чтобы таблица не выглядела как «сломанная».
func reviewMarkdownCell(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return escapeMarkdownCell(s)
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
// reportUpdatedAt — если не nil, в шапку добавляется строка о времени последнего обновления отчёта (например после ручного review).
func RenderMarkdown(jobName, baseURL, preset string, started, finished time.Time, findings []model.Finding, evidence map[string]model.Evidence, includeEvidence bool, evidenceThreshold string, reportUpdatedAt *time.Time) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# DAST Report\n\n")
	fmt.Fprintf(&b, "- **Job**: %s\n", jobName)
	fmt.Fprintf(&b, "- **Target**: %s\n", baseURL)
	fmt.Fprintf(&b, "- **Preset**: %s\n", preset)
	fmt.Fprintf(&b, "- **Started**: %s\n", started.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Finished**: %s\n", finished.UTC().Format(time.RFC3339))
	if reportUpdatedAt != nil {
		fmt.Fprintf(&b, "- **Report last updated**: %s\n", reportUpdatedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "\n## Executive summary\n\n")
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
	fmt.Fprintf(&b, "- Confirmed: %d\n- Unconfirmed / detected: %d\n- Suppressed: %d\n\n", confirmed, unconf, suppressed)
	fmt.Fprintf(&b, "### By severity\n\n")
	fmt.Fprintf(&b, "Уровни **CRITICAL** и **HIGH** соответствуют наиболее опасным находкам. Ниже всегда приведены все уровни; **0** означает, что находок этого уровня нет.\n\n")
	for _, s := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		fmt.Fprintf(&b, "- **%s**: %d\n", s, bySev[s])
	}
	th := strings.TrimSpace(evidenceThreshold)
	if th == "" {
		th = "low"
	}
	if len(findings) > 0 {
		fmt.Fprintf(&b, "\n## Evidence summary\n\n")
		fmt.Fprintf(&b, "HTTP evidence quality vs threshold **%s**: **sufficient** — порог выполнен; **partial** — есть HTTP, но не дотягивает до порога; **non-http** — только не-HTTP артефакты; **none** — нет ссылок на evidence.\n\n", th)
		fmt.Fprintf(&b, "| Finding ID | Rule | Severity | Status | Evidence refs | Quality |\n")
		fmt.Fprintf(&b, "|------------|------|----------|--------|---------------|--------|\n")
		for _, f := range findings {
			rule := escapeMarkdownCell(f.RuleID)
			q := noise.FindingEvidenceQualityLabel(f, evidence, th)
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %d | %s |\n", f.FindingID, rule, f.Severity, f.LifecycleStatus, len(f.EvidenceRefs), q)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Findings\n\n")
	fmt.Fprintf(&b, "Колонки **Reviewer**, **Reviewed at** и **Review note** заполняются только после ручного review находки (поля `reviewedBy` / `reviewedAt` / `reviewNote` в модели finding); при чисто автоматическом скане там остаётся «—».\n\n")
	fmt.Fprintf(&b, "| Severity | Status | Rule | Location | Title | Reviewer | Reviewed at | Review note |\n")
	fmt.Fprintf(&b, "|----------|--------|------|----------|-------|----------|-------------|-------------|\n")
	for _, f := range findings {
		title := escapeMarkdownCell(f.Title)
		reviewer := reviewMarkdownCell(f.ReviewedBy)
		note := reviewMarkdownCell(f.ReviewNote)
		reviewedAt := "—"
		if f.ReviewedAt != nil {
			reviewedAt = f.ReviewedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", f.Severity, f.LifecycleStatus, f.RuleID, f.LocationKey, title, reviewer, reviewedAt, note)
	}
	if includeEvidence {
		fmt.Fprintf(&b, "\n## Evidence\n\n")
		for _, f := range sortedFindingsBySeverity(findings) {
			var printedHeader bool
			for _, eid := range f.EvidenceRefs {
				ev, ok := evidence[eid]
				if !ok {
					continue
				}
				if ev.Type == model.EvidenceManualReview {
					continue
				}
				if !printedHeader {
					title := escapeMarkdownCell(f.Title)
					fmt.Fprintf(&b, "### Finding `%s` — %s — %s — %s\n\n", f.FindingID, f.Severity, f.LifecycleStatus, title)
					printedHeader = true
				}
				fmt.Fprintf(&b, "#### Evidence `%s` (%s)\n\n", eid, ev.Type)
				b.WriteString(formatEvidenceMarkdown(ev))
				b.WriteString("\n")
			}
		}
	}
	if hasManualReviewEvidence(findings, evidence) {
		fmt.Fprintf(&b, "\n## Audit trail (manual review)\n\n")
		for _, f := range findings {
			for _, eid := range f.EvidenceRefs {
				ev, ok := evidence[eid]
				if !ok || ev.Type != model.EvidenceManualReview {
					continue
				}
				fmt.Fprintf(&b, "### Finding %s — evidence `%s`\n\n", f.FindingID, eid)
				b.WriteString(formatManualReviewEvidence(ev))
				b.WriteString("\n")
			}
		}
	}
	return b.Bytes()
}

func hasManualReviewEvidence(findings []model.Finding, evidence map[string]model.Evidence) bool {
	for _, f := range findings {
		for _, eid := range f.EvidenceRefs {
			if ev, ok := evidence[eid]; ok && ev.Type == model.EvidenceManualReview {
				return true
			}
		}
	}
	return false
}

func reportSeverityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

func sortedFindingsBySeverity(findings []model.Finding) []model.Finding {
	out := slices.Clone(findings)
	sort.Slice(out, func(i, j int) bool {
		ri := reportSeverityRank(out[i].Severity)
		rj := reportSeverityRank(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return out[i].LocationKey < out[j].LocationKey
	})
	return out
}

func formatManualReviewEvidence(ev model.Evidence) string {
	var b strings.Builder
	switch p := ev.Payload.(type) {
	case map[string]any:
		if v, ok := p["action"]; ok {
			fmt.Fprintf(&b, "- **action**: %v\n", v)
		}
		if v, ok := p["actor"]; ok {
			fmt.Fprintf(&b, "- **actor**: %v\n", v)
		}
		if v, ok := p["note"]; ok && fmt.Sprintf("%v", v) != "" {
			fmt.Fprintf(&b, "- **note**: %v\n", v)
		}
		if v, ok := p["previousLifecycle"]; ok && fmt.Sprintf("%v", v) != "" {
			fmt.Fprintf(&b, "- **previous lifecycle**: %v\n", v)
		}
	case model.ManualReviewPayload:
		fmt.Fprintf(&b, "- **action**: %s\n", p.Action)
		fmt.Fprintf(&b, "- **actor**: %s\n", p.Actor)
		if p.Note != "" {
			fmt.Fprintf(&b, "- **note**: %s\n", p.Note)
		}
		if p.PreviousLifecycle != "" {
			fmt.Fprintf(&b, "- **previous lifecycle**: %s\n", p.PreviousLifecycle)
		}
	default:
		fmt.Fprintf(&b, "- **payload**: %v\n", ev.Payload)
	}
	if ev.ContextID != "" {
		fmt.Fprintf(&b, "- **contextId**: %s\n", ev.ContextID)
	}
	return b.String()
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
