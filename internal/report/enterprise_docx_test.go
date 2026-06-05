package report

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestWriteEnterpriseDocx_hasTables_noEndpoints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.docx")
	now := time.Now().UTC()
	endpoints := make([]string, 5000)
	for i := range endpoints {
		endpoints[i] = "https://example.com/path/" + string(rune('a'+i%26))
	}
	err := WriteEnterpriseDocx(Data{
		JobName:          "job-1",
		BaseURL:          "https://example.com",
		Preset:           "Fast",
		Started:          now,
		Finished:         now,
		ScannedEndpoints: endpoints,
		IncludeEvidence:  true,
		Findings: []model.Finding{{
			RuleID:           "10038",
			Title:            "Missing CSP",
			Severity:         model.SeverityMedium,
			LifecycleStatus:  model.LifecycleConfirmed,
		}},
	}, path)
	if err != nil {
		t.Fatal(err)
	}
	xml := readDocxDocumentXML(t, path)
	if !strings.Contains(xml, "<w:tbl>") {
		t.Fatal("expected Word table elements (w:tbl) in document.xml")
	}
	if !strings.Contains(xml, `w:fill="F2F2F2"`) {
		t.Fatal("expected corporate table header shading F2F2F2")
	}
	if strings.Contains(xml, "Scanned Endpoints") || strings.Contains(xml, "просканировано") {
		t.Fatal("report must not list scanned endpoints")
	}
	if !strings.Contains(xml, "Отчёт") || !strings.Contains(xml, "о проведении тестирования безопасности") {
		t.Fatal("expected enterprise Russian title")
	}
	if strings.Contains(xml, "DAST Report") {
		t.Fatal("legacy DAST Report title must not appear")
	}
}

func readDocxDocumentXML(t *testing.T, path string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, rc); err != nil {
			rc.Close()
			t.Fatal(err)
		}
		rc.Close()
		return buf.String()
	}
	t.Fatal("missing word/document.xml")
	return ""
}
