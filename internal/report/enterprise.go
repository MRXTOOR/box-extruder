package report

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

// RenderEnterpriseMarkdown builds a Russian security test report in the same
// structure as the corporate SAST/SCA Word template (Общие сведения, методы,
// состав, таблица уязвимостей).
func RenderEnterpriseMarkdown(d Data) []byte {
	product := productNameFromData(d)
	reportDate := d.Finished.UTC().Format("02.01.2006")
	if reportDate == "01.01.0001" || d.Finished.IsZero() {
		reportDate = time.Now().UTC().Format("02.01.2006")
	}

	findings := enterpriseReportFindings(d.Findings)

	var b bytes.Buffer
	b.WriteString("# Отчёт о проведении тестирования безопасности программного продукта\n\n")
	b.WriteString("## Общие сведения\n\n")
	b.WriteString("| Параметр | Значение |\n| --- | --- |\n")
	deliveryID := strings.TrimSpace(d.JobName)
	if deliveryID == "" {
		deliveryID = "—"
	}
	methods := "DAST (AppSec-DAST): Katana; OWASP ZAP Baseline; Wapiti; Nuclei"
	fmt.Fprintf(&b, "| Наименование ПО | %s |\n", mdCell(product))
	fmt.Fprintf(&b, "| Версия ПО | %s |\n", mdCell(d.Preset))
	fmt.Fprintf(&b, "| Идентификатор поставки | %s |\n", mdCell(deliveryID))
	fmt.Fprintf(&b, "| Дата формирования отчёта | %s |\n", mdCell(reportDate))
	fmt.Fprintf(&b, "| Целевой URL | %s |\n", mdCell(d.BaseURL))
	fmt.Fprintf(&b, "| Период тестирования | %s — %s |\n",
		mdCell(d.Started.UTC().Format("02.01.2006 15:04")),
		mdCell(d.Finished.UTC().Format("02.01.2006 15:04")))
	fmt.Fprintf(&b, "| Методы тестирования | %s |\n", mdCell(methods))

	b.WriteString("\n## Цель тестирования\n\n")
	b.WriteString("Целью тестирования является выявление уязвимостей и ошибок конфигурации ")
	b.WriteString("веб-приложения в ходе эксплуатации (runtime) в соответствии с требованиями ")
	b.WriteString("безопасности и подтверждение соответствия заявленному уровню защищённости.\n")

	b.WriteString("\n## Состав и границы тестирования\n\n")
	b.WriteString("**Тестируемый компонент:** веб-приложение ")
	fmt.Fprintf(&b, "`%s`", d.BaseURL)
	b.WriteString(" и обнаруженные в ходе сканирования эндпоинты.\n\n")
	b.WriteString("**Методика:** динамический анализ безопасности приложения (DAST).\n")

	b.WriteString("\n## Результаты тестирования\n\n")
	b.WriteString("### Выявленные уязвимости и ошибки конфигурации\n\n")
	if len(findings) == 0 {
		b.WriteString("По результатам DAST-сканирования подтверждённых уязвимостей не выявлено.\n")
	} else {
		b.WriteString("| № | Идентификатор | Описание | Тип анализа | Уровень критичности | Статус |\n")
		b.WriteString("| ---: | --- | --- | --- | --- | --- |\n")
		for i, f := range findings {
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n",
				i+1,
				mdCell(findingIdentifier(f)),
				mdCell(findingDescription(f)),
				mdCell(analysisType(f)),
				mdCell(severityRU(f.Severity)),
				mdCell(lifecycleRU(f.LifecycleStatus)),
			)
		}
	}

	writeEnterpriseSeveritySummary(&b, findings)
	writeEnterpriseRemediationSection(&b)
	writeEnterpriseConclusionsSection(&b, findings)

	return b.Bytes()
}

func writeEnterpriseSeveritySummary(b *bytes.Buffer, findings []model.Finding) {
	bySev := enterpriseSeverityCounts(findings)
	if len(bySev) == 0 {
		return
	}
	b.WriteString("\n### Распределение по уровню критичности\n\n")
	b.WriteString("| Уровень | Количество |\n| --- | ---: |\n")
	for _, sev := range []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow,
	} {
		if n := bySev[sev]; n > 0 {
			fmt.Fprintf(b, "| %s | %d |\n", severityRU(sev), n)
		}
	}
}

func writeEnterpriseRemediationSection(b *bytes.Buffer) {
	b.WriteString("\n### Рекомендации по устранению уязвимостей\n\n")
	b.WriteString(remediationRecommendationsText)
	b.WriteString("\n")
}

func writeEnterpriseConclusionsSection(b *bytes.Buffer, findings []model.Finding) {
	b.WriteString("\n### Выводы\n\n")
	b.WriteString(formatConclusions(findings))
	b.WriteString("\n")
}

func productNameFromData(d Data) string {
	if d.BaseURL != "" {
		if u, err := url.Parse(d.BaseURL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if d.JobName != "" {
		return d.JobName
	}
	return "Веб-приложение"
}

func severityRU(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "Критический"
	case model.SeverityHigh:
		return "Высокий"
	case model.SeverityMedium:
		return "Средний"
	case model.SeverityLow:
		return "Низкий"
	case model.SeverityInfo:
		return "Информационный"
	default:
		return string(s)
	}
}

func lifecycleRU(st model.LifecycleStatus) string {
	switch st {
	case model.LifecycleConfirmed:
		return "Подтверждён"
	case model.LifecycleFalsePositiveSuppressed:
		return "Ложное срабатывание"
	case model.LifecycleUnconfirmed:
		return "Не подтверждён"
	case model.LifecycleRecheckRequired:
		return "Требует перепроверки"
	default:
		return "Открыт"
	}
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
