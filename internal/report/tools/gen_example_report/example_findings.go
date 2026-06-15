//go:build ignore

package main

import (
	"github.com/box-extruder/dast/internal/model"
)

// exampleFindings returns sample findings for the enterprise report demo.
func exampleFindings() []model.Finding {
	base := exampleBaseURL()
	out := exampleZapHeaderFindings(base)
	out = append(out, exampleNucleiFindings(base)...)
	out = append(out, exampleZapCookieFindings(base)...)
	out = append(out, exampleMiscFindings(base)...)
	return out
}

func exampleZapHeaderFindings(base string) []model.Finding {
	return []model.Finding{
		{
			FindingID: "f-001", RuleID: "10038", Category: "zap",
			Title: "Content Security Policy (CSP) Header Not Set",
			Description: "Отсутствует заголовок Content-Security-Policy. Это может позволить атаки XSS и загрузку вредоносного контента.",
			Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/",
		},
		{
			FindingID: "f-002", RuleID: "10020", Category: "zap",
			Title: "X-Frame-Options Header Not Set",
			Description: "Отсутствует заголовок X-Frame-Options или CSP frame-ancestors. Возможна атака clickjacking.",
			Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/",
		},
		{
			FindingID: "f-003", RuleID: "10021", Category: "zap",
			Title: "X-Content-Type-Options Header Missing",
			Description: "Отсутствует заголовок X-Content-Type-Options: nosniff.",
			Severity: model.SeverityLow, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/assets/index-vJDItvOT.js",
		},
		{
			FindingID: "f-004", RuleID: "10035", Category: "zap",
			Title: "Strict-Transport-Security Header Not Set",
			Description: "HSTS не настроен. Возможны атаки downgrade HTTPS.",
			Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/",
		},
	}
}

func exampleNucleiFindings(base string) []model.Finding {
	return []model.Finding{
		{
			FindingID: "f-005", RuleID: "http-missing-security-headers", Category: "nuclei",
			Title: "Missing Security Headers",
			Description: "Обнаружены ответы без рекомендуемых заголовков безопасности.",
			Severity: model.SeverityLow, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: exampleURL("/api/v1/subscriptions/plans"),
		},
		{
			FindingID: "f-006", RuleID: "exposed-panels", Category: "nuclei",
			Title: "Exposed Admin Panel",
			Description: "Обнаружен потенциально доступный административный интерфейс.",
			Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/auth/",
		},
	}
}

func exampleZapCookieFindings(base string) []model.Finding {
	return []model.Finding{
		{
			FindingID: "f-007", RuleID: "cookie-without-secure", Category: "zap",
			Title: "Cookie Without Secure Flag",
			Description: "Cookie передаётся без флага Secure.",
			Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/payment/",
		},
		{
			FindingID: "f-008", RuleID: "cookie-without-httponly", Category: "zap",
			Title: "Cookie Without HttpOnly Flag",
			Description: "Cookie доступен из JavaScript, что повышает риск XSS.",
			Severity: model.SeverityMedium, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/auth/",
		},
	}
}

func exampleMiscFindings(base string) []model.Finding {
	return []model.Finding{
		{
			FindingID: "f-009", RuleID: "robots-txt", Category: "nuclei",
			Title: "robots.txt Information Disclosure",
			Description: "Файл robots.txt раскрывает структуру приложения.",
			Severity: model.SeverityInfo, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/robots.txt",
		},
		{
			FindingID: "f-010", RuleID: "cors-misconfig", Category: "wapiti",
			Title: "CORS Misconfiguration",
			Description: "Небезопасная конфигурация CORS: Access-Control-Allow-Origin: *.",
			Severity: model.SeverityHigh, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: exampleURL("/api/"),
		},
		{
			FindingID: "f-011", RuleID: "10027", Category: "zap",
			Title: "Information Disclosure — Suspicious Comments",
			Description: "В HTML/JS обнаружены комментарии с потенциально чувствительной информацией.",
			Severity: model.SeverityInfo, LifecycleStatus: model.LifecycleUnconfirmed,
			LocationKey: base + "/assets/index-vJDItvOT.js",
		},
		{
			FindingID: "f-012", RuleID: "tls-weak-cipher", Category: "nuclei",
			Title: "Weak TLS Cipher Suite",
			Description: "Сервер поддерживает устаревшие наборы шифров TLS.",
			Severity: model.SeverityLow, LifecycleStatus: model.LifecycleConfirmed,
			LocationKey: base + "/",
		},
	}
}
