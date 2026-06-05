package report

import (
	"fmt"
	"os"
	"os/exec"
)

// EnsurePdfReport renders report.pdf from corporate HTML via wkhtmltopdf.
func EnsurePdfReport(htmlPath, pdfPath string) error {
	if _, err := os.Stat(htmlPath); err != nil {
		return fmt.Errorf("html report missing: %w", err)
	}
	if _, err := exec.LookPath("wkhtmltopdf"); err != nil {
		return fmt.Errorf("wkhtmltopdf not installed: %w", err)
	}
	cmd := exec.Command("wkhtmltopdf",
		"--encoding", "utf-8",
		"--enable-local-file-access",
		"--margin-top", "15mm",
		"--margin-bottom", "15mm",
		"--margin-left", "15mm",
		"--margin-right", "15mm",
		htmlPath, pdfPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wkhtmltopdf: %w: %s", err, string(out))
	}
	return nil
}
