package noise

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
)

// Apply runs dedupe, suppression, and progressive confirmation heuristics.
func Apply(cfg config.ScanAsCode, in []model.Finding, evidenceByID map[string]model.Evidence) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	seen := map[string]struct{}{}
	for _, f := range in {
		f.LocationKey = BuildLocationKey(cfg.Noise.Dedupe, f)
		key := f.LocationKey + "|" + f.RuleID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if ok, reason := matchSuppression(cfg.Noise.Suppression.Exclude, f); ok {
			f.LifecycleStatus = model.LifecycleFalsePositiveSuppressed
			if reason != "" {
				f.SuppressionReason = reason
			} else {
				f.SuppressionReason = "matched exclude rule"
			}
		}
		_ = matchAllowlist(cfg.Noise.Suppression.Allowlist, f)
		f = applyProgressive(cfg, f, evidenceByID)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].LocationKey < out[j].LocationKey
	})
	return out
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

// BuildLocationKey normalizes endpoint+method+params per config.
func BuildLocationKey(d config.DedupeConfig, f model.Finding) string {
	if f.LocationKey != "" && d.LocationKey == "" {
		return f.LocationKey
	}
	// Parse from Title/Description fallback: expect URL embedded in first evidence
	return f.LocationKey
}

// BuildLocationKeyFromHTTP builds key from method and raw URL.
func BuildLocationKeyFromHTTP(d config.DedupeConfig, method, rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		m := strings.ToUpper(strings.TrimSpace(method))
		if m == "" {
			m = "GET"
		}
		return m + " (unknown URL)"
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToUpper(method) + " " + rawURL
	}
	endpoint := u.Scheme + "://" + u.Host + u.Path
	q := u.Query()
	var keys []string
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			if d.ParamNormalization == "deep" {
				v = normalizeParamValue(v)
			}
			parts = append(parts, k+"="+v)
		}
	}
	paramStr := strings.Join(parts, "&")
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	loc := m + " " + endpoint
	if paramStr != "" {
		loc += "?" + paramStr
	}
	return loc
}

func normalizeParamValue(v string) string {
	if len(v) > 8 && isDigitOrHex(v) {
		return "{id}"
	}
	return v
}

func isDigitOrHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && c != '-' {
			return false
		}
	}
	return true
}

func matchSuppression(rules []config.SuppressionRule, f model.Finding) (bool, string) {
	for _, r := range rules {
		if r.RuleID != "" && r.RuleID != f.RuleID {
			continue
		}
		if r.Category != "" && !strings.EqualFold(r.Category, f.Category) {
			continue
		}
		if r.Severity != "" && !strings.EqualFold(r.Severity, string(f.Severity)) {
			continue
		}
		if r.LocationKey != "" && r.LocationKey != f.LocationKey {
			continue
		}
		if r.Endpoint != "" && !strings.Contains(f.LocationKey, r.Endpoint) {
			continue
		}
		if r.RuleID != "" || r.Category != "" || r.Severity != "" || r.LocationKey != "" || r.Endpoint != "" {
			return true, r.Reason
		}
	}
	return false, ""
}

func matchAllowlist(rules []config.SuppressionRule, f model.Finding) bool {
	for _, r := range rules {
		if r.LocationKey != "" && r.LocationKey == f.LocationKey {
			return true
		}
	}
	return false
}

func applyProgressive(cfg config.ScanAsCode, f model.Finding, evidenceByID map[string]model.Evidence) model.Finding {
	if !cfg.EffectiveProgressiveConfirmation() {
		return f
	}
	th := strings.ToLower(strings.TrimSpace(cfg.Budgets.Verification.EvidenceThreshold))
	if th == "" {
		th = "low"
	}
	var hasAnyHTTP bool
	var hasSufficient bool
	for _, id := range f.EvidenceRefs {
		ev, ok := evidenceByID[id]
		if !ok || ev.Type != model.EvidenceHTTPRequestResponse {
			continue
		}
		hasAnyHTTP = true
		if HTTPEvidenceMeetsThreshold(ev, th) {
			hasSufficient = true
			break
		}
	}
	confirm := hasSufficient || (th == "low" && hasAnyHTTP)
	switch f.LifecycleStatus {
	case model.LifecycleFalsePositiveSuppressed:
		return f
	case model.LifecycleDetected:
		if !hasAnyHTTP && th != "low" {
			f.LifecycleStatus = model.LifecycleUnconfirmed
		} else if confirm {
			f.LifecycleStatus = model.LifecycleConfirmed
			f.LastSeenAt = time.Now().UTC()
		} else {
			f.LifecycleStatus = model.LifecycleUnconfirmed
		}
	case model.LifecycleUnconfirmed:
		if confirm {
			f.LifecycleStatus = model.LifecycleConfirmed
			f.LastSeenAt = time.Now().UTC()
		}
	case model.LifecycleConfirmed:
		// keep
	}
	return f
}
