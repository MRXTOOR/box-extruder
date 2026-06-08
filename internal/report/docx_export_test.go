package report

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestWriteDocxFromData_validZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.docx")
	now := time.Now().UTC()
	err := EnsureDocxReport(Data{
		JobName:  "test-job",
		BaseURL:  "https://app.example.com",
		Preset:   "Fast",
		Started:  now,
		Finished: now,
		Findings: []model.Finding{{
			RuleID:   "rule-1",
			Title:    "Test finding",
			Severity: model.SeverityHigh,
		}},
	}, path, "")
	if err != nil {
		t.Fatal(err)
	}
	xml := readDocxDocumentXML(t, path)
	if !strings.Contains(xml, "<w:tbl>") {
		t.Fatal("EnsureDocxReport must produce Word tables")
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var hasDoc bool
	for _, f := range zr.File {
		if docxZipEntry(f.Name) == "word/document.xml" {
			hasDoc = true
		}
	}
	if !hasDoc {
		t.Fatal("missing word/document.xml in docx")
	}
	st, _ := os.Stat(path)
	if st.Size() < 200 {
		t.Fatalf("docx too small: %d", st.Size())
	}
}
