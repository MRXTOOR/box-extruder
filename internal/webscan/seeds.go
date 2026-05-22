package webscan

import (
	"net/url"
	"strings"
)

// inferStartPointsFromLoginURL adds SPA app roots when login lives under /api/... (e.g. /app/ppau/api/auth/login).
func inferStartPointsFromLoginURL(loginURL string) []string {
	u, err := url.Parse(strings.TrimSpace(loginURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	path := u.Path
	i := strings.Index(path, "/api/")
	if i <= 0 {
		return nil
	}
	app := strings.TrimSuffix(path[:i], "/")
	if app == "" {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	return []string{origin + app + "/", origin + app}
}

func mergeStartPoints(existing, extra []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, list := range [][]string{existing, extra} {
		for _, u := range list {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}
