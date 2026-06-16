package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

// WriteEnterpriseDocx builds report.docx using the corporate template package
// (styles, numbering, headers) and table markup from enterprise-reference.docx.
func WriteEnterpriseDocx(d Data, path string) error {
	loadTemplateDocumentShell()
	if templateDocOpen == "" {
		return fmt.Errorf("enterprise docx template shell not loaded")
	}

	meta := enterpriseDocxMeta(d)
	var body bytes.Buffer
	writeEnterpriseDocxSections(&body, d, meta)

	var doc bytes.Buffer
	doc.WriteString(templateDocOpen)
	doc.Write(body.Bytes())
	doc.WriteString(templateSectPr)
	doc.WriteString(templateDocClose)

	out := doc.Bytes()
	if !bytes.HasPrefix(out, []byte("<?xml")) {
		out = append([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`), out...)
	}
	return cloneDocxWithDocument(out, path)
}

type enterpriseDocxMetaFields struct {
	product, reportDate, period, deliveryID, methods string
}

func enterpriseDocxMeta(d Data) enterpriseDocxMetaFields {
	product := productNameFromData(d)
	reportDate := d.Finished.UTC().Format("02.01.2006")
	if d.Finished.IsZero() {
		reportDate = time.Now().UTC().Format("02.01.2006")
	}
	period := d.Started.UTC().Format("02.01.2006 15:04") + " — " + d.Finished.UTC().Format("02.01.2006 15:04")
	deliveryID := strings.TrimSpace(d.JobName)
	if deliveryID == "" {
		deliveryID = "—"
	}
	methods := "Динамический анализ безопасности приложения (DAST, Black-box), платформа AppSec-DAST:\n" +
		"Katana — обход и сбор URL веб-приложения;\n" +
		"OWASP ZAP Baseline — автоматизированное сканирование веб-уязвимостей;\n" +
		"Wapiti — поиск уязвимостей на обнаруженных эндпоинтах;\n" +
		"Nuclei — проверка по шаблонам известных уязвимостей."
	return enterpriseDocxMetaFields{product, reportDate, period, deliveryID, methods}
}

func writeEnterpriseDocxSections(body *bytes.Buffer, d Data, meta enterpriseDocxMetaFields) {
	corpTitle(body)
	corpSection(body, 1, "Общие сведения")
	corpInfoTable(body, [][2]string{
		{"Наименование ПО", meta.product},
		{"Версия ПО", d.Preset},
		{"Идентификатор поставки", meta.deliveryID},
		{"Дата формирования отчета", meta.reportDate},
		{"Целевой URL", d.BaseURL},
		{"Период тестирования", meta.period},
		{"Методы тестирования", meta.methods},
	})

	corpSection(body, 1, "Цель тестирования")
	corpBody(body, "Целью тестирования является выявление уязвимостей и ошибок конфигурации "+
		"веб-приложения в ходе эксплуатации (runtime) в соответствии с требованиями безопасности "+
		"и подтверждение соответствия заявленному уровню защищённости.")

	corpSection(body, 1, "Состав и границы тестирования")
	corpBody(body, "Тестируемый компонент: веб-приложение "+d.BaseURL+" и обнаруженные в ходе сканирования эндпоинты.")
	corpBody(body, "Методика: динамический анализ безопасности приложения (DAST).")

	corpSection(body, 1, "Результаты тестирования")
	corpSection(body, 2, "Выявленные уязвимости и ошибки конфигурации")
	writeEnterpriseFindingsSection(body, enterpriseReportFindings(d.Findings))
}

func writeEnterpriseFindingsSection(body *bytes.Buffer, findings []model.Finding) {
	if len(findings) == 0 {
		corpBody(body, "По результатам DAST-сканирования подтверждённых уязвимостей не выявлено.")
		writeEnterpriseConclusionsDocx(body, findings)
		return
	}
	headers := []string{"№", "Идентификатор", "Описание", "Тип анализа", "Уровень критичности", "Статус"}
	rows := make([][]string, 0, len(findings))
	for i, f := range findings {
		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1),
			findingIdentifier(f),
			truncateForCell(findingDescription(f), 1200),
			analysisType(f),
			severityRU(f.Severity),
			lifecycleRU(f.LifecycleStatus),
		})
	}
	corpFindingsTable(body, headers, rows, corpFindingColWidths)

	bySev := enterpriseSeverityCounts(findings)
	if len(bySev) > 0 {
		corpSection(body, 2, "Распределение по уровню критичности")
		sevPairs := make([][2]string, 0)
		for _, sev := range []model.Severity{
			model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow,
		} {
			if n := bySev[sev]; n > 0 {
				sevPairs = append(sevPairs, [2]string{severityRU(sev), fmt.Sprintf("%d", n)})
			}
		}
		if len(sevPairs) > 0 {
			corpInfoTable(body, sevPairs)
		}
	}

	corpSection(body, 2, "Рекомендации по устранению уязвимостей")
	corpBody(body, remediationRecommendationsText)
	writeEnterpriseConclusionsDocx(body, findings)
}

func writeEnterpriseConclusionsDocx(body *bytes.Buffer, findings []model.Finding) {
	corpSection(body, 2, "Выводы")
	corpBody(body, "На основании проведённого тестирования:")
	corpBody(body, "• выявлено "+conclusionsTotalPhrase(findings)+", из них:")

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
		corpBodyIndented(body, fmt.Sprintf("•\t%s – %d%s", line.label, line.n, end), 720)
	}
	corpBody(body, conclusionsAssessmentPhrase(findings))
}

func truncateForCell(s string, max int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
