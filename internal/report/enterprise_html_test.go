package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestWriteEnterpriseHTMLReport_tables(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/report.html"
	now := time.Now().UTC()
	err := WriteEnterpriseHTMLReport(Data{
		JobName:  "job-1",
		BaseURL:  "https://app.example.com",
		Preset:   "custom",
		Started:  now,
		Finished: now,
		Findings: []model.Finding{{
			RuleID:          "10038",
			Title:           "CSP missing",
			Severity:        model.SeverityMedium,
			LifecycleStatus: model.LifecycleDetected,
			Category:        "zap",
		}},
	}, path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	s := string(raw)
	for _, want := range []string{"<table", "Общие сведения", "Идентификатор", "Тип анализа", "Средний"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in html", want)
		}
	}
}
