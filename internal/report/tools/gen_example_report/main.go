//go:build ignore

// Generates docs/examples/dast-enterprise-report-example.{docx,html} with sample data.
// Run from repo root: go run internal/report/tools/gen_example_report/main.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/box-extruder/dast/internal/report"
)

const exampleDemoHost = "example.com"

func exampleBaseURL() string {
	return "https://" + exampleDemoHost
}

func exampleURL(path string) string {
	if path == "" || path == "/" {
		return exampleBaseURL() + "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	return exampleBaseURL() + path
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	outDir := filepath.Join(root, "docs", "examples")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}

	data := exampleData()
	docxPath := filepath.Join(outDir, "dast-enterprise-report-example.docx")
	htmlPath := filepath.Join(outDir, "dast-enterprise-report-example.html")

	if err := report.WriteEnterpriseDocx(data, docxPath); err != nil {
		fatal(fmt.Errorf("docx: %w", err))
	}
	if err := report.WriteEnterpriseHTMLReport(data, htmlPath); err != nil {
		fatal(fmt.Errorf("html: %w", err))
	}

	for _, p := range []string{docxPath, htmlPath} {
		st, err := os.Stat(p)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", p, st.Size())
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// exampleData mirrors a Fast-preset scan in corporate report layout (fictional demo target).
func exampleData() report.Data {
	started := time.Date(2026, 6, 4, 3, 42, 6, 0, time.UTC)
	finished := time.Date(2026, 6, 4, 6, 26, 4, 0, time.UTC)

	return report.Data{
		JobName:  "10bdb66f-917b-4f9f-9273-77f30e055cd4",
		BaseURL:  exampleBaseURL(),
		Preset:   "Fast",
		Started:  started,
		Finished: finished,
		Findings: exampleFindings(),
	}
}
