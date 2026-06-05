package report

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteScanReports generates HTML, DOCX and PDF (enterprise template; no endpoint/evidence dumps).
func WriteScanReports(data Data, reportsDir, referenceDocx string) error {
	pub := data
	pub.ScannedEndpoints = nil
	pub.IncludeEvidence = false
	pub.Evidence = nil

	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return err
	}
	htmlPath := filepath.Join(reportsDir, "report.html")
	docxPath := filepath.Join(reportsDir, "report.docx")
	pdfPath := filepath.Join(reportsDir, "report.pdf")

	if err := WriteEnterpriseHTMLReport(pub, htmlPath); err != nil {
		return fmt.Errorf("html report: %w", err)
	}
	if err := EnsureDocxReport(pub, docxPath, referenceDocx); err != nil {
		return fmt.Errorf("docx report: %w", err)
	}
	if err := EnsurePdfReport(htmlPath, pdfPath); err != nil {
		return fmt.Errorf("pdf report: %w", err)
	}
	return nil
}
