package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestRenderEnterpriseMarkdown_structure(t *testing.T) {
	now := time.Now().UTC()
	md := string(RenderEnterpriseMarkdown(Data{
		JobName:  "scan-abc",
		BaseURL:  "https://app.example.com",
		Preset:   "custom",
		Started:  now.Add(-time.Hour),
		Finished: now,
		Findings: []model.Finding{{
			RuleID:          "CVE-2025-00001",
			Title:           "Test issue",
			Severity:        model.SeverityHigh,
			LifecycleStatus: model.LifecycleDetected,
			Category:        "zap",
		}},
	}))
	for _, want := range []string{
		"Отчёт о проведении тестирования безопасности",
		"Общие сведения",
		"Методы тестирования",
		"Katana",
		"ZAP",
		"Цель тестирования",
		"Состав и границы тестирования",
		"Результаты тестирования",
		"Идентификатор",
		"Тип анализа",
		"Уровень критичности",
		"Высокий",
		"Открыт",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q", want)
		}
	}
}

func TestEnterpriseReferenceDocPath(t *testing.T) {
	p, err := EnterpriseReferenceDocPath()
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Size() <= 1000 {
		t.Fatalf("reference doc missing or too small: %s", p)
	}
}
