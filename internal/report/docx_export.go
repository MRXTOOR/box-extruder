package report

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// EnsureDocxReport writes report.docx with native Word tables (корпоративный DAST).
// referenceDocx is ignored: pandoc overwrite removed tables and reintroduced legacy layout.
func EnsureDocxReport(data Data, docxPath, _ string) error {
	pub := data
	pub.ScannedEndpoints = nil
	pub.IncludeEvidence = false
	pub.Evidence = nil
	return WriteEnterpriseDocx(pub, docxPath)
}

func pandocDocxFromMarkdown(mdPath, docxPath, referenceDocx string) error {
	if _, err := exec.LookPath("pandoc"); err != nil {
		return err
	}
	args := []string{"-f", "markdown+pipe_tables", mdPath, "-o", docxPath}
	if referenceDocx != "" {
		args = append(args, "--reference-doc="+referenceDocx)
	}
	cmd := exec.Command("pandoc", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pandoc: %w: %s", err, string(out))
	}
	return nil
}

func tryPandocDocx(mdPath, htmlPath, docxPath, referenceDocx string) error {
	if _, err := exec.LookPath("pandoc"); err != nil {
		return err
	}
	if mdPath != "" {
		if st, err := os.Stat(mdPath); err == nil && st.Size() > 0 {
			if err := PandocToDocx(mdPath, docxPath, referenceDocx); err == nil {
				return nil
			}
		}
	}
	if htmlPath != "" {
		if st, err := os.Stat(htmlPath); err == nil && st.Size() > 0 {
			return PandocToDocx(htmlPath, docxPath, referenceDocx)
		}
	}
	return fmt.Errorf("pandoc: no source files")
}

// WriteDocxFromData builds a native Word document with tables.
func WriteDocxFromData(data Data, docxPath string) error {
	return EnsureDocxReport(data, docxPath, "")
}

func escapeDocxText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
