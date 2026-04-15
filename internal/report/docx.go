package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func RenderDocxOptional(jobName, baseURL string, started, finished time.Time, findings []model.Finding, scannedEndpoints []string, outputPath string) error {
	htmlPath := filepath.Join(filepath.Dir(outputPath), "report.html")
	return writeHTMLReport(jobName, baseURL, started, finished, findings, scannedEndpoints, htmlPath)
}

func writeHTMLReport(jobName, baseURL string, started, finished time.Time, findings []model.Finding, scannedEndpoints []string, htmlPath string) error {
	var html strings.Builder

	html.WriteString(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DAST Security Report</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 14px; line-height: 1.6; color: #1a1a2e; background: #f0f2f5; padding: 2rem; }
.container { max-width: 900px; margin: 0 auto; }
.card { background: #fff; border-radius: 12px; padding: 1.5rem 2rem; margin-bottom: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.header { text-align: center; padding: 2rem; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #fff; border-radius: 12px; margin-bottom: 1.5rem; }
.header h1 { font-size: 2rem; margin-bottom: 0.5rem; }
.header p { opacity: 0.8; }
h2 { font-size: 1.3rem; color: #16213e; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 3px solid #e94560; }
h3 { font-size: 1.1rem; color: #333; margin: 1.5rem 0 0.75rem; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem; }
.meta-item { background: #f8f9fa; padding: 0.75rem 1rem; border-radius: 8px; border-left: 4px solid #e94560; }
.meta-item strong { display: block; font-size: 0.85rem; color: #666; margin-bottom: 0.25rem; }
.severity-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-top: 1rem; }
.severity-card { text-align: center; padding: 1.25rem; border-radius: 10px; }
.severity-card .count { font-size: 2.5rem; font-weight: 700; line-height: 1; margin-bottom: 0.5rem; }
.severity-card .label { font-size: 0.85rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.critical { background: #fff5f5; border: 2px solid #e94560; } .critical .count { color: #e94560; } .critical .label { color: #c0392b; }
.high { background: #fff8f0; border: 2px solid #e67e22; } .high .count { color: #e67e22; } .high .label { color: #d35400; }
.medium { background: #fffef5; border: 2px solid #f1c40f; } .medium .count { color: #d4a500; } .medium .label { color: #b8960c; }
.low { background: #f0f7ff; border: 2px solid #3498db; } .low .count { color: #3498db; } .low .label { color: #2980b9; }
.info { background: #f8f9fa; border: 2px solid #95a5a6; } .info .count { color: #7f8c8d; } .info .label { color: #95a5a6; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e1e4e8; }
th { background: #f6f8fa; font-weight: 600; color: #24292e; }
tr:hover td { background: #f6f8fa; }
.endpoint-url { font-family: monospace; font-size: 0.85rem; color: #0366d6; word-break: break-all; }
.finding-rule { font-family: monospace; font-size: 0.8rem; background: #f1f8ff; padding: 0.2rem 0.4rem; border-radius: 4px; color: #0366d6; }
.badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 500; }
.badge-confirmed { background: #d4edda; color: #155724; } .badge-detected { background: #fff3cd; color: #856404; } .badge-suppressed { background: #e2e3e5; color: #383d41; }
.section-divider { height: 2px; background: linear-gradient(90deg, transparent, #e1e4e8, transparent); margin: 2rem 0; }
.no-findings { text-align: center; padding: 2rem; color: #28a745; font-size: 1.1rem; }
.no-findings .icon { font-size: 3rem; margin-bottom: 1rem; }
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>DAST Security Report</h1>
  <p>Результаты автоматизированного динамического анализа безопасности</p>
</div>
<div class="card">
  <h2>Информация о сканировании</h2>
  <div class="meta-grid">
    <div class="meta-item"><strong>Сканирование</strong>` + " " + escapeHTML(jobName) + `</div>
    <div class="meta-item"><strong>Целевой URL</strong>` + " " + escapeHTML(baseURL) + `</div>
    <div class="meta-item"><strong>Начало</strong>` + " " + started.UTC().Format("02.01.2006 15:04:05") + `</div>
    <div class="meta-item"><strong>Завершение</strong>` + " " + finished.UTC().Format("02.01.2006 15:04:05") + `</div>
  </div>
</div>
`)

	bySev := map[model.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}

	html.WriteString(fmt.Sprintf(`
<div class="card">
  <h2>Executive Summary</h2>
  <div class="severity-grid">
    <div class="severity-card critical"><div class="count">%d</div><div class="label">CRITICAL</div></div>
    <div class="severity-card high"><div class="count">%d</div><div class="label">HIGH</div></div>
    <div class="severity-card medium"><div class="count">%d</div><div class="label">MEDIUM</div></div>
    <div class="severity-card low"><div class="count">%d</div><div class="label">LOW</div></div>
    <div class="severity-card info"><div class="count">%d</div><div class="label">INFO</div></div>
  </div>
</div>
`,
		bySev[model.SeverityCritical],
		bySev[model.SeverityHigh],
		bySev[model.SeverityMedium],
		bySev[model.SeverityLow],
		bySev[model.SeverityInfo],
	))

	if len(scannedEndpoints) > 0 {
		html.WriteString(fmt.Sprintf(`
<div class="card">
  <h2>Просканированные эндпоинты</h2>
  <p>Всего просканировано эндпоинтов: <strong>%d</strong></p>
  <table><thead><tr><th>#</th><th>Endpoint</th></tr></thead><tbody>
`, len(scannedEndpoints)))
		for i, ep := range scannedEndpoints {
			html.WriteString(fmt.Sprintf("<tr><td>%d</td><td><span class=\"endpoint-url\">%s</span></td></tr>\n", i+1, escapeHTML(ep)))
		}
		html.WriteString("</tbody></table></div>\n")
	}

	html.WriteString(`
<div class="card">
  <h2>Findings</h2>
`)

	if len(findings) == 0 {
		html.WriteString(`<div class="no-findings"><div class="icon">OK</div><p>Уязвимостей не обнаружено!</p></div>`)
	} else {
		severities := []struct {
			sev model.Severity
		}{
			{model.SeverityCritical},
			{model.SeverityHigh},
			{model.SeverityMedium},
			{model.SeverityLow},
			{model.SeverityInfo},
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

			html.WriteString(fmt.Sprintf(`<div class="section-divider"></div><h3>%s (%d)</h3><table><thead><tr><th>#</th><th>Rule</th><th>Status</th><th>Title</th></tr></thead><tbody>`,
				sev.sev, len(sevFindings)))

			for i, f := range sevFindings {
				statusClass := "badge-detected"
				if f.LifecycleStatus == model.LifecycleConfirmed {
					statusClass = "badge-confirmed"
				} else if f.LifecycleStatus == model.LifecycleFalsePositiveSuppressed {
					statusClass = "badge-suppressed"
				}
				html.WriteString(fmt.Sprintf("<tr><td>%d</td><td><span class=\"finding-rule\">%s</span></td><td><span class=\"badge %s\">%s</span></td><td>%s</td></tr>\n",
					i+1, escapeHTML(f.RuleID), statusClass, escapeHTML(string(f.LifecycleStatus)), escapeHTML(f.Title)))
			}
			html.WriteString("</tbody></table>\n")
		}
	}

	html.WriteString("</div></div></body></html>")

	return os.WriteFile(htmlPath, []byte(html.String()), 0o644)
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
