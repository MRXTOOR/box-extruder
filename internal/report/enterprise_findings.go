package report

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
)

var (
	cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
	cwePattern = regexp.MustCompile(`(?i)CWE-\d+`)
)

const remediationRecommendationsText = "Для критических и высоких уязвимостей срок исправления составляет до 30 календарных дней, " +
	"для средних и низких – до 90 календарных дней. Сроки исправления уязвимостей всех уровней критичности должны также " +
	"учитывать возможные дополнительные рекомендации Группы ТБ и/или локальных нормативных актов. Обработка начинается " +
	"сразу же после выявления уязвимости и включает в себя её анализ, разработку плана устранения и исправления.\n" +
	"В случае, если уязвимость не устранена в установленный срок, ответственный за устранение обязан уведомить " +
	"непосредственного руководителя и Группу ТБ о причинах неустранения уязвимости, предоставив соответствующую " +
	"аргументацию к заявке на устранение. Если ответственный не уведомил о причинах неустранения и не предоставил " +
	"аргументацию в установленный срок, то заявка эскалируется на владельца продукта и вышестоящее руководство."

// enterpriseReportFindings returns confirmed, non-informational findings for the corporate report.
func enterpriseReportFindings(in []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		if f.LifecycleStatus == model.LifecycleFalsePositiveSuppressed {
			continue
		}
		if f.LifecycleStatus != model.LifecycleConfirmed {
			continue
		}
		if f.Severity == model.SeverityInfo {
			continue
		}
		out = append(out, f)
	}
	return out
}

func enterpriseSeverityCounts(findings []model.Finding) map[model.Severity]int {
	bySev := map[model.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	return bySev
}

func analysisType(_ model.Finding) string {
	return "DAST"
}

func findingIdentifier(f model.Finding) string {
	if cwe := extractCWE(f); cwe != "" {
		return strings.ToUpper(cwe)
	}
	if cve := extractCVE(f); cve != "" {
		return strings.ToUpper(cve)
	}
	rid := strings.TrimSpace(f.RuleID)
	for _, prefix := range []string{"wapiti:", "zap:", "nuclei:", "katana:"} {
		if strings.HasPrefix(strings.ToLower(rid), prefix) {
			rid = strings.TrimSpace(rid[len(prefix):])
			break
		}
	}
	if rid != "" {
		return rid
	}
	return stripToolPrefix(f.Title)
}

func findingDescription(f model.Finding) string {
	var parts []string

	main := findingMainTextRU(f)
	if main != "" {
		parts = append(parts, main)
	}
	if ep := endpointFromFinding(f); ep != "" {
		parts = append(parts, ep)
	}
	if refs := findingExternalRefs(f); refs != "" {
		parts = append(parts, refs)
	}
	return strings.Join(parts, ". ")
}

func findingMainTextRU(f model.Finding) string {
	desc := strings.TrimSpace(f.Description)
	if hasCyrillic(desc) {
		desc = cleanScannerDescription(desc)
		if desc != "" {
			return desc
		}
	}
	title := humanFindingTitle(f)
	if ru := translateFindingTitle(title); ru != "" {
		if desc != "" && !hasCyrillic(desc) {
			return ru + ". " + desc
		}
		return ru
	}
	if title != "" {
		return title
	}
	return desc
}

func humanFindingTitle(f model.Finding) string {
	if t := stripToolPrefix(f.Title); t != "" {
		return t
	}
	if c := strings.TrimSpace(f.Category); c != "" {
		return c
	}
	return strings.TrimSpace(f.RuleID)
}

func stripToolPrefix(s string) string {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{"Wapiti:", "ZAP:", "Nuclei:", "Katana:"} {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimSpace(s[len(prefix):])
		}
	}
	return s
}

func cleanScannerDescription(s string) string {
	lines := strings.Split(s, "\n")
	var kept []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "module:") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, " ")
}

func endpointFromFinding(f model.Finding) string {
	if ep := strings.TrimSpace(noise.EndpointURLFromLocationKey(f.LocationKey)); ep != "" {
		return ep
	}
	loc := strings.TrimSpace(f.LocationKey)
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	return ""
}

func findingExternalRefs(f model.Finding) string {
	cve := extractCVE(f)
	cwe := extractCWE(f)
	switch {
	case cve != "" && cwe != "":
		return cve + ", " + cwe
	case cve != "":
		return cve
	case cwe != "":
		return cwe
	default:
		return ""
	}
}

func extractCVE(f model.Finding) string {
	for _, s := range []string{f.RuleID, f.Title, f.Description, f.Category} {
		if m := cvePattern.FindString(s); m != "" {
			return strings.ToUpper(m)
		}
	}
	return ""
}

func extractCWE(f model.Finding) string {
	for _, s := range []string{f.RuleID, f.Title, f.Description, f.Category} {
		if m := cwePattern.FindString(s); m != "" {
			return strings.ToUpper(m)
		}
	}
	if cwe := zapRuleToCWE(f.RuleID); cwe != "" {
		return cwe
	}
	return ""
}

func zapRuleToCWE(ruleID string) string {
	switch strings.TrimSpace(ruleID) {
	case "10038":
		return "CWE-693"
	case "10020":
		return "CWE-1021"
	case "10021":
		return "CWE-693"
	case "10035":
		return "CWE-319"
	case "10027":
		return "CWE-200"
	case "10054":
		return "CWE-614"
	case "10096":
		return "CWE-1275"
	default:
		return ""
	}
}

func hasCyrillic(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

func translateFindingTitle(title string) string {
	key := strings.ToLower(strings.TrimSpace(title))
	if key == "" {
		return ""
	}
	if ru, ok := findingTitleRU[key]; ok {
		return ru
	}
	for en, ru := range findingTitleRU {
		if strings.Contains(key, en) {
			return ru
		}
	}
	return ""
}

var findingTitleRU = map[string]string{
	"content security policy configuration": "Небезопасная конфигурация Content Security Policy (CSP)",
	"content security policy (csp) header not set": "Отсутствует заголовок Content-Security-Policy (CSP)",
	"x-frame-options header not set":            "Отсутствует заголовок X-Frame-Options (риск clickjacking)",
	"x-content-type-options header missing":     "Отсутствует заголовок X-Content-Type-Options",
	"strict-transport-security header not set":  "Не настроен заголовок Strict-Transport-Security (HSTS)",
	"missing security headers":                  "Отсутствуют рекомендуемые заголовки безопасности",
	"exposed admin panel":                       "Обнаружена потенциально доступная административная панель",
	"cookie without secure flag":                "Cookie передаётся без флага Secure",
	"cookie without httponly flag":              "Cookie доступен из JavaScript (отсутствует HttpOnly)",
	"robots.txt information disclosure":         "Файл robots.txt раскрывает структуру приложения",
	"cors misconfiguration":                     "Небезопасная конфигурация CORS",
	"information disclosure — suspicious comments": "Раскрытие информации в комментариях HTML/JS",
	"weak tls cipher suite":                     "Используются слабые наборы шифров TLS",
	"sql injection":                             "Возможная SQL-инъекция",
}

type securityAssessment struct {
	Level       string
	Explanation string
}

func assessSecurityLevel(findings []model.Finding) securityAssessment {
	counts := enterpriseSeverityCounts(findings)
	critical := counts[model.SeverityCritical]
	high := counts[model.SeverityHigh]
	medium := counts[model.SeverityMedium]
	low := counts[model.SeverityLow]
	total := critical + high + medium + low

	if hasSQLInjectionFinding(findings) {
		return securityAssessment{
			Level:       "низкий",
			Explanation: "выявлены уязвимости класса SQL-инъекция; требуется немедленное устранение",
		}
	}
	if critical >= 1 || high >= 1 {
		return securityAssessment{
			Level:       "низкий",
			Explanation: "требуется устранение критических и высоких уязвимостей перед внедрением в промышленную эксплуатацию",
		}
	}
	if total == 0 {
		return securityAssessment{
			Level:       "высокий",
			Explanation: "значимых подтверждённых уязвимостей не выявлено",
		}
	}
	if medium == 0 {
		return securityAssessment{
			Level:       "высокий",
			Explanation: "критических, высоких и средних уязвимостей не выявлено",
		}
	}
	if medium == 1 && low >= 10 {
		return securityAssessment{
			Level:       "высокий",
			Explanation: "выявлены преимущественно уязвимости низкого уровня",
		}
	}
	if total > 0 && float64(medium)/float64(total) <= 0.20 {
		return securityAssessment{
			Level:       "средний",
			Explanation: "доля уязвимостей среднего уровня в пределах допустимого порога; рекомендуется плановое устранение",
		}
	}
	return securityAssessment{
		Level:       "средний",
		Explanation: "выявлено значительное количество уязвимостей среднего уровня; рекомендуется устранение в установленные сроки",
	}
}

func hasSQLInjectionFinding(findings []model.Finding) bool {
	for _, f := range findings {
		blob := strings.ToLower(findingIdentifier(f) + " " + humanFindingTitle(f) + " " + f.Title + " " + f.Description + " " + f.RuleID)
		if strings.Contains(blob, "sql injection") || strings.Contains(blob, "sql-инъек") || strings.Contains(blob, "sqli") {
			return true
		}
	}
	return false
}

func formatConclusions(findings []model.Finding) string {
	counts := enterpriseSeverityCounts(findings)
	total := counts[model.SeverityCritical] + counts[model.SeverityHigh] +
		counts[model.SeverityMedium] + counts[model.SeverityLow]
	assess := assessSecurityLevel(findings)

	var b strings.Builder
	b.WriteString("На основании проведённого тестирования:\n")
	b.WriteString("• выявлено ")
	if total == 0 {
		b.WriteString("0 уязвимостей и ошибок конфигураций")
	} else {
		b.WriteString(pluralVuln(total))
	}
	b.WriteString(", из них:\n")
	b.WriteString(formatSeverityBullet("критических", counts[model.SeverityCritical], false))
	b.WriteString(formatSeverityBullet("высокого уровня", counts[model.SeverityHigh], false))
	b.WriteString(formatSeverityBullet("среднего уровня", counts[model.SeverityMedium], false))
	b.WriteString(formatSeverityBullet("низкого уровня", counts[model.SeverityLow], true))
	b.WriteString("• Программный продукт имеет ")
	b.WriteString(assess.Level)
	b.WriteString(" уровень защищённости")
	if assess.Explanation != "" {
		b.WriteString(" (")
		b.WriteString(assess.Explanation)
		b.WriteString(")")
	}
	b.WriteString(".")
	return b.String()
}

func pluralVuln(n int) string {
	mod10 := n % 10
	mod100 := n % 100
	switch {
	case mod10 == 1 && mod100 != 11:
		return fmtInt(n) + " уязвимость и ошибка конфигурации"
	case mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20):
		return fmtInt(n) + " уязвимости и ошибки конфигураций"
	default:
		return fmtInt(n) + " уязвимостей и ошибок конфигураций"
	}
}

func formatSeverityBullet(label string, n int, last bool) string {
	end := ",\n"
	if last {
		end = ".\n"
	}
	return "•\t" + label + " – " + fmtInt(n) + end
}

func conclusionsTotalPhrase(findings []model.Finding) string {
	counts := enterpriseSeverityCounts(findings)
	total := counts[model.SeverityCritical] + counts[model.SeverityHigh] +
		counts[model.SeverityMedium] + counts[model.SeverityLow]
	if total == 0 {
		return "0 уязвимостей и ошибок конфигураций"
	}
	return pluralVuln(total)
}

func conclusionsAssessmentPhrase(findings []model.Finding) string {
	assess := assessSecurityLevel(findings)
	line := "• Программный продукт имеет " + assess.Level + " уровень защищённости"
	if assess.Explanation != "" {
		line += " (" + assess.Explanation + ")"
	}
	return line + "."
}

func fmtInt(n int) string {
	return strconv.Itoa(n)
}
