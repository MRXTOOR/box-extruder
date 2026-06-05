package discovery

import (
	"net/url"
	"sort"
	"strings"
)

// CandidateAuthURLs returns login endpoint URLs to try, in priority order.
// When explicitAuthURL is set, only that URL is returned.
func CandidateAuthURLs(targetURL, explicitAuthURL string, insecureSkipTLS bool) []string {
	explicit := strings.TrimSpace(explicitAuthURL)
	if explicit != "" {
		return []string{explicit}
	}

	seen := make(map[string]struct{})
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
	}

	target := strings.TrimSpace(targetURL)
	if looksLikeLoginURL(target) {
		add(target)
	}

	if u, err := url.Parse(target); err == nil && u.Scheme != "" && u.Host != "" {
		base := strings.TrimRight(u.Scheme+"://"+u.Host, "/")
		for _, p := range []string{
			"/api/v1/auth/login",
			"/api/auth/login",
			"/api/v1/login",
			"/api/login",
			"/auth/login",
			"/auth/signin",
			"/login",
			"/signin",
			"/sign-in",
			"/account/login",
			"/user/login",
		} {
			add(base + p)
		}
	}

	surface := DiscoverSurface(target, insecureSkipTLS)
	for _, u := range surface.LoginURLs {
		add(u)
	}
	for _, u := range surface.Forms {
		add(u)
	}

	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Strings(out)
	// Prefer API-style endpoints before bare site root / generic /login.
	sort.SliceStable(out, func(i, j int) bool {
		return authURLPriority(out[i]) < authURLPriority(out[j])
	})
	return out
}

func authURLPriority(raw string) int {
	p := strings.ToLower(raw)
	switch {
	case strings.Contains(p, "/api/") && strings.Contains(p, "login"):
		return 0
	case strings.Contains(p, "/api/") && strings.Contains(p, "auth"):
		return 1
	case strings.Contains(p, "/auth/"):
		return 2
	case strings.Contains(p, "/login"):
		return 3
	default:
		return 10
	}
}
