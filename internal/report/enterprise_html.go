package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

// WriteEnterpriseHTMLReport writes report.html (корпоративный DAST-отчёт с таблицами).
func WriteEnterpriseHTMLReport(d Data, htmlPath string) error {
	product := productNameFromData(d)
	reportDate := d.Finished.UTC().Format("02.01.2006")
	if d.Finished.IsZero() {
		reportDate = time.Now().UTC().Format("02.01.2006")
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Отчёт о тестировании безопасности (DAST)</title>
<style>
  body { font-family: Arial, "Segoe UI", sans-serif; font-size: 11pt; line-height: 1.45; color: #1a1a2e; margin: 2cm; }
  h1 { text-align: center; font-size: 18pt; text-transform: uppercase; margin: 0 0 1.5rem; color: #1f3763; }
  h2 { font-size: 13pt; color: #2f5496; border-bottom: 2px solid #2f5496; padding-bottom: 0.25rem; margin: 1.5rem 0 0.75rem; }
  h3 { font-size: 12pt; color: #1f3763; margin: 1rem 0 0.5rem; }
  p { margin: 0.5rem 0; text-align: justify; }
  table { width: 100%; border-collapse: collapse; margin: 0.75rem 0 1rem; font-size: 10pt; }
  th, td { border: 1px solid #444; padding: 6px 8px; vertical-align: top; }
  th { background: #f0f4f8; font-weight: 600; text-align: left; }
  td.num { text-align: center; width: 3em; }
  ul { margin: 0.5rem 0 1rem 1.25rem; }
  .meta-label { width: 38%; font-weight: 600; background: #f8f9fa; }
  .empty { text-align: center; padding: 1rem; color: #28a745; }
</style>
</head>
<body>
`)
	b.WriteString(`<h1>Отчёт о проведении тестирования безопасности программного продукта</h1>`)

	deliveryID := strings.TrimSpace(d.JobName)
	if deliveryID == "" {
		deliveryID = "—"
	}
	methods := "Динамический анализ безопасности приложения (DAST, Black-box), платформа AppSec-DAST:\n" +
		"Katana — обход и сбор URL веб-приложения;\n" +
		"OWASP ZAP Baseline — автоматизированное сканирование веб-уязвимостей;\n" +
		"Wapiti — поиск уязвимостей на обнаруженных эндпоинтах;\n" +
		"Nuclei — проверка по шаблонам известных уязвимостей."

	b.WriteString(`<h2>Общие сведения</h2><table>`)
	writeMetaRow(&b, "Параметр", "Значение", true)
	writeMetaRow(&b, "Наименование ПО", product, false)
	writeMetaRow(&b, "Версия ПО", d.Preset, false)
	writeMetaRow(&b, "Идентификатор поставки", deliveryID, false)
	writeMetaRow(&b, "Дата формирования отчёта", reportDate, false)
	writeMetaRow(&b, "Целевой URL", d.BaseURL, false)
	writeMetaRow(&b, "Период тестирования",
		d.Started.UTC().Format("02.01.2006 15:04")+" — "+d.Finished.UTC().Format("02.01.2006 15:04"), false)
	writeMetaRow(&b, "Методы тестирования", methods, false)
	b.WriteString(`</table>`)

	b.WriteString(`<h2>Цель тестирования</h2>
<p>Выявление уязвимостей и ошибок конфигурации веб-приложения в ходе эксплуатации (runtime)
в соответствии с требованиями безопасности и подтверждение заявленного уровня защищённости.</p>`)

	b.WriteString(`<h2>Состав и границы тестирования</h2>
<p><strong>Тестируемый компонент:</strong> `)
	b.WriteString(`<code>` + escapeHTML(d.BaseURL) + `</code> и обнаруженные в ходе сканирования эндпоинты.`)
	b.WriteString(`</p>
<p><strong>Методика:</strong> динамический анализ безопасности приложения (DAST).</p>`)

	findings := enterpriseReportFindings(d.Findings)

	b.WriteString(`<h2>Результаты тестирования</h2><h3>Выявленные уязвимости и ошибки конфигурации</h3>`)
	if len(findings) == 0 {
		b.WriteString(`<p class="empty">По результатам DAST-сканирования подтверждённых уязвимостей не выявлено.</p>`)
	} else {
		b.WriteString(`<table><thead><tr>
<th class="num">№</th><th>Идентификатор</th><th>Описание</th><th>Тип анализа</th><th>Уровень критичности</th><th>Статус</th>
</tr></thead><tbody>`)
		for i, f := range findings {
			fmt.Fprintf(&b, `<tr><td class="num">%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				i+1,
				escapeHTML(findingIdentifier(f)),
				escapeHTML(findingDescription(f)),
				escapeHTML(analysisType(f)),
				escapeHTML(severityRU(f.Severity)),
				escapeHTML(lifecycleRU(f.LifecycleStatus)),
			)
		}
		b.WriteString(`</tbody></table>`)

		bySev := enterpriseSeverityCounts(findings)
		if len(bySev) > 0 {
			b.WriteString(`<h3>Распределение по уровню критичности</h3><table><thead><tr><th>Уровень</th><th>Количество</th></tr></thead><tbody>`)
			for _, sev := range []model.Severity{
				model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow,
			} {
				if n := bySev[sev]; n > 0 {
					fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(severityRU(sev)), n)
				}
			}
			b.WriteString(`</tbody></table>`)
		}
	}

	b.WriteString(`<h3>Рекомендации по устранению уязвимостей</h3><p>`)
	b.WriteString(escapeHTMLMultiline(remediationRecommendationsText))
	b.WriteString(`</p>`)

	b.WriteString(`<h3>Выводы</h3>`)
	b.WriteString(`<p>На основании проведённого тестирования:</p>`)
	b.WriteString(`<p>• выявлено ` + escapeHTML(conclusionsTotalPhrase(findings)) + `, из них:</p>`)
	b.WriteString(`<ul style="list-style-type:none;padding-left:1.5em">`)
	counts := enterpriseSeverityCounts(findings)
	severityLines := []struct {
		label string
		n     int
	}{
		{"критических", counts[model.SeverityCritical]},
		{"высокого уровня", counts[model.SeverityHigh]},
		{"среднего уровня", counts[model.SeverityMedium]},
		{"низкого уровня", counts[model.SeverityLow]},
	}
	for i, line := range severityLines {
		end := ","
		if i == len(severityLines)-1 {
			end = "."
		}
		fmt.Fprintf(&b, `<li>• %s – %d%s</li>`, escapeHTML(line.label), line.n, end)
	}
	b.WriteString(`</ul>`)
	b.WriteString(`<p>` + escapeHTML(conclusionsAssessmentPhrase(findings)) + `</p>`)
	b.WriteString(`</body></html>`)
	return os.WriteFile(htmlPath, []byte(b.String()), 0o644)
}

func writeMetaRow(b *strings.Builder, label, value string, header bool) {
	if header {
		b.WriteString(`<tr><th class="meta-label">`)
		b.WriteString(escapeHTML(label))
		b.WriteString(`</th><th>`)
		b.WriteString(escapeHTML(value))
		b.WriteString(`</th></tr>`)
		return
	}
	b.WriteString(`<tr><td class="meta-label">`)
	b.WriteString(escapeHTML(label))
	b.WriteString(`</td><td>`)
	b.WriteString(escapeHTMLMultiline(value))
	b.WriteString(`</td></tr>`)
}

func escapeHTMLMultiline(s string) string {
	s = escapeHTML(s)
	return strings.ReplaceAll(s, "\n", "<br>")
}
