//go:build ignore

// Generates docs/examples/dast-enterprise-report-example.{docx,html} with sample data.
// Run from repo root: go run internal/report/tools/gen_example_report/main.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/report"
)

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

// exampleData mirrors a real Fast-preset scan (kubikvpn.com) in corporate report layout.
func exampleData() report.Data {
	started := time.Date(2026, 6, 4, 3, 42, 6, 0, time.UTC)
	finished := time.Date(2026, 6, 4, 6, 26, 4, 0, time.UTC)

	return report.Data{
		JobName:  "10bdb66f-917b-4f9f-9273-77f30e055cd4",
		BaseURL:  "https://kubikvpn.com",
		Preset:   "Fast",
		Started:  started,
		Finished: finished,
		Findings: []model.Finding{
			{
				FindingID: "f-001", RuleID: "10038", Category: "zap",
				Title: "Content Security Policy (CSP) Header Not Set",
				Description: "Отсутствует заголовок Content-Security-Policy. Это может позволить атаки XSS и загрузку вредоносного контента.",
				Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/",
			},
			{
				FindingID: "f-002", RuleID: "10020", Category: "zap",
				Title: "X-Frame-Options Header Not Set",
				Description: "Отсутствует заголовок X-Frame-Options или CSP frame-ancestors. Возможна атака clickjacking.",
				Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/",
			},
			{
				FindingID: "f-003", RuleID: "10021", Category: "zap",
				Title: "X-Content-Type-Options Header Missing",
				Description: "Отсутствует заголовок X-Content-Type-Options: nosniff.",
				Severity: model.SeverityLow, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/assets/index-vJDItvOT.js",
			},
			{
				FindingID: "f-004", RuleID: "10035", Category: "zap",
				Title: "Strict-Transport-Security Header Not Set",
				Description: "HSTS не настроен. Возможны атаки downgrade HTTPS.",
				Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/",
			},
			{
				FindingID: "f-005", RuleID: "http-missing-security-headers", Category: "nuclei",
				Title: "Missing Security Headers",
				Description: "Обнаружены ответы без рекомендуемых заголовков безопасности.",
				Severity: model.SeverityLow, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/api/v1/subscriptions/plans",
			},
			{
				FindingID: "f-006", RuleID: "exposed-panels", Category: "nuclei",
				Title: "Exposed Admin Panel",
				Description: "Обнаружен потенциально доступный административный интерфейс.",
				Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/auth/",
			},
			{
				FindingID: "f-007", RuleID: "cookie-without-secure", Category: "zap",
				Title: "Cookie Without Secure Flag",
				Description: "Cookie передаётся без флага Secure.",
				Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/payment/",
			},
			{
				FindingID: "f-008", RuleID: "cookie-without-httponly", Category: "zap",
				Title: "Cookie Without HttpOnly Flag",
				Description: "Cookie доступен из JavaScript, что повышает риск XSS.",
				Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/auth/",
			},
			{
				FindingID: "f-009", RuleID: "robots-txt", Category: "nuclei",
				Title: "robots.txt Information Disclosure",
				Description: "Файл robots.txt раскрывает структуру приложения.",
				Severity: model.SeverityInfo, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/robots.txt",
			},
			{
				FindingID: "f-010", RuleID: "cors-misconfig", Category: "wapiti",
				Title: "CORS Misconfiguration",
				Description: "Небезопасная конфигурация CORS: Access-Control-Allow-Origin: *.",
				Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/api/",
			},
			{
				FindingID: "f-011", RuleID: "10027", Category: "zap",
				Title: "Information Disclosure — Suspicious Comments",
				Description: "В HTML/JS обнаружены комментарии с потенциально чувствительной информацией.",
				Severity: model.SeverityInfo, LifecycleStatus: model.LifecycleUnconfirmed,
				LocationKey: "https://kubikvpn.com/assets/index-vJDItvOT.js",
			},
			{
				FindingID: "f-012", RuleID: "tls-weak-cipher", Category: "nuclei",
				Title: "Weak TLS Cipher Suite",
				Description: "Сервер поддерживает устаревшие наборы шифров TLS.",
				Severity: model.SeverityLow, LifecycleStatus: model.LifecycleConfirmed,
				LocationKey: "https://kubikvpn.com/",
			},
		},
	}
}
