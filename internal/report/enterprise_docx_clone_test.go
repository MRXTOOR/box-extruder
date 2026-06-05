package report

import (
	"archive/zip"
	"testing"
)

func TestWriteEnterpriseDocx_usesTemplatePackage(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/report.docx"
	if err := WriteEnterpriseDocx(Data{
		JobName: "j", BaseURL: "https://x.test", Preset: "Fast",
	}, path); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var hasStyles, hasNumbering, hasHeader bool
	for _, f := range zr.File {
		switch f.Name {
		case "word/styles.xml":
			hasStyles = true
		case "word/numbering.xml":
			hasNumbering = true
		case "word/header1.xml":
			hasHeader = true
		}
	}
	if !hasStyles || !hasNumbering {
		t.Fatal("docx must retain corporate template styles and numbering")
	}
	if !hasHeader {
		t.Fatal("docx must retain corporate header from template")
	}
}
