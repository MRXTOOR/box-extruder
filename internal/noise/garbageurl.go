package noise

import (
	"net/url"
	"regexp"
	"strings"
)

var garbageDiscoveryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)PUBLIC_URL`),
	regexp.MustCompile(`%25.*%25`),
	regexp.MustCompile(`(?i)/manifest\.json(\?.*)?$`),
	regexp.MustCompile(`(?i)/static/`),
}

// IsGarbageDiscoveryURL reports SPA/build artifacts and other URLs that should not
// enter the discovery feed or ZAP requestor probes.
func IsGarbageDiscoveryURL(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return true
	}
	if IsAttackPayloadURL(rawURL) {
		return true
	}
	for _, re := range garbageDiscoveryPatterns {
		if re.MatchString(rawURL) {
			return true
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if strings.Contains(strings.ToLower(u.Path), "public_url") {
		return true
	}
	return false
}
