package discovery

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// SurfaceResult is the legacy enterprise discover response shape.
type SurfaceResult struct {
	TargetURL string   `json:"targetUrl"`
	Forms     []string `json:"forms"`
	LoginURLs []string `json:"loginUrls"`
}

var (
	formActionRe = regexp.MustCompile(`(?i)<form[^>]*action\s*=\s*["']([^"']+)["']`)
	hrefRe       = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	loginPathRe  = regexp.MustCompile(`(?i)(/login|/signin|/sign-in|/auth|/account/login|/user/login|/session/new)`)
)

// DiscoverSurface fetches targetUrl and extracts form actions and login-like URLs (no credentials).
func DiscoverSurface(targetURL string, insecureSkipTLS bool) SurfaceResult {
	out := SurfaceResult{TargetURL: strings.TrimSpace(targetURL)}
	if out.TargetURL == "" {
		return out
	}
	base, err := url.Parse(out.TargetURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return out
	}

	client := newHTTPClient(insecureSkipTLS)
	body, finalURL := fetchHTML(client, out.TargetURL)
	if body == "" {
		return out
	}
	if u, err := url.Parse(finalURL); err == nil && u.Scheme != "" && u.Host != "" {
		base = u
		out.TargetURL = strings.TrimRight(u.String(), "/")
	}

	seenForms := make(map[string]struct{})
	seenLogin := make(map[string]struct{})
	addForm := func(raw string) {
		abs := resolveRef(base, raw)
		if abs == "" {
			return
		}
		if _, ok := seenForms[abs]; ok {
			return
		}
		seenForms[abs] = struct{}{}
		out.Forms = append(out.Forms, abs)
	}
	addLogin := func(raw string) {
		abs := resolveRef(base, raw)
		if abs == "" {
			return
		}
		if !looksLikeLoginURL(abs) {
			return
		}
		if _, ok := seenLogin[abs]; ok {
			return
		}
		seenLogin[abs] = struct{}{}
		out.LoginURLs = append(out.LoginURLs, abs)
	}

	for _, m := range formActionRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			addForm(m[1])
		}
	}
	// Forms without explicit action submit to the current page.
	if strings.Contains(strings.ToLower(body), "<form") {
		addForm(out.TargetURL)
	}

	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			addLogin(m[1])
		}
	}
	for _, guess := range []string{"/login", "/signin", "/sign-in", "/auth/login", "/#/login"} {
		addLogin(guess)
	}

	sort.Strings(out.Forms)
	sort.Strings(out.LoginURLs)
	if out.Forms == nil {
		out.Forms = []string{}
	}
	if out.LoginURLs == nil {
		out.LoginURLs = []string{}
	}
	return out
}

func fetchHTML(client *http.Client, raw string) (body string, finalURL string) {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return "", raw
	}
	req.Header.Set("User-Agent", "AppSec-DAST-auth-discovery/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return "", raw
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	final := raw
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", final
	}
	return string(data), final
}

func resolveRef(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(strings.ToLower(ref), "javascript:") {
		return ""
	}
	u, err := base.Parse(ref)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return strings.TrimRight(u.String(), "/")
}

func looksLikeLoginURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	if loginPathRe.MatchString(path) {
		return true
	}
	if strings.Contains(strings.ToLower(u.Fragment), "login") {
		return true
	}
	q := strings.ToLower(u.RawQuery)
	return strings.Contains(q, "login") || strings.Contains(q, "signin")
}
