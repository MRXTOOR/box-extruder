package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
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
	docXML := readDocxDocumentXML(t, path)
	if !strings.Contains(docXML, "<w:tbl>") {
		t.Fatal("expected Word table elements (w:tbl) in document.xml")
	}
	if !strings.Contains(docXML, `w:fill="F2F2F2"`) {
		t.Fatal("expected corporate table header shading F2F2F2")
	}
	if strings.Contains(docXML, "Scanned Endpoints") || strings.Contains(docXML, "просканировано") {
		t.Fatal("report must not list scanned endpoints")
	}
	if !strings.Contains(docXML, "Отчёт") || !strings.Contains(docXML, "о проведении тестирования безопасности") {
		t.Fatal("expected enterprise Russian title")
	}
	if strings.Contains(docXML, "DAST Report") {
		t.Fatal("legacy DAST Report title must not appear")
	}
	if !strings.Contains(docXML, "<w:sectPr") {
		t.Fatal("document must include w:sectPr section properties")
	}
	if strings.Contains(docXML, "</w:rPr><w:r><w:rPr>") {
		t.Fatal("malformed nested w:r in table cells")
	}
	dec := xml.NewDecoder(strings.NewReader(docXML))
	for {
		if _, err := dec.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("document.xml is not well-formed: %v", err)
		}
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
		if docxZipEntry(f.Name) != "word/document.xml" {
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
