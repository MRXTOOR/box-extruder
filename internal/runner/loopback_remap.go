package runner

import (
	"net/url"
	"os"
	"strings"

	"github.com/box-extruder/dast/internal/config"
)

const loopbackHostGateway = "host.docker.internal"

// applyLoopbackRemapForContainer rewrites localhost/127.0.0.1/::1 URLs to host.docker.internal
// when worker runs inside Docker. This allows scanning host-local targets from a containerized worker.
func applyLoopbackRemapForContainer(cfg *config.ScanAsCode) bool {
	if cfg == nil || !shouldRemapLoopback() {
		return false
	}
	changed := false
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if v, ok := remapLoopbackURL(t.BaseURL); ok {
			t.BaseURL = v
			changed = true
		}
		for j := range t.StartPoints {
			if v, ok := remapLoopbackURL(t.StartPoints[j]); ok {
				t.StartPoints[j] = v
				changed = true
			}
		}
		for j := range t.ExcludeURLs {
			if v, ok := remapLoopbackURL(t.ExcludeURLs[j]); ok {
				t.ExcludeURLs[j] = v
				changed = true
			}
		}
		for j := range t.IncludeURLs {
			if v, ok := remapLoopbackURL(t.IncludeURLs[j]); ok {
				t.IncludeURLs[j] = v
				changed = true
			}
		}
	}
	for i := range cfg.Scope.Allow {
		if v, ok := remapLoopbackRegex(cfg.Scope.Allow[i]); ok {
			cfg.Scope.Allow[i] = v
			changed = true
		}
	}
	for i := range cfg.Scope.Deny {
		if v, ok := remapLoopbackRegex(cfg.Scope.Deny[i]); ok {
			cfg.Scope.Deny[i] = v
			changed = true
		}
	}
	if cfg.Auth != nil {
		for i := range cfg.Auth.Providers {
			p := &cfg.Auth.Providers[i]
			if p.GenericLogin != nil {
				if v, ok := remapLoopbackURL(p.GenericLogin.LoginURL); ok {
					p.GenericLogin.LoginURL = v
					changed = true
				}
				if v, ok := remapLoopbackURL(p.GenericLogin.VerifyURL); ok {
					p.GenericLogin.VerifyURL = v
					changed = true
				}
			}
			if p.Verification != nil && p.Verification.Details != nil {
				if raw, ok := p.Verification.Details["url"].(string); ok {
					if v, changedURL := remapLoopbackURL(raw); changedURL {
						p.Verification.Details["url"] = v
						changed = true
					}
				}
			}
			for _, k := range []string{"verifyUrl", "tokenEndpoint", "issuer"} {
				raw := strings.TrimSpace(p.Config[k])
				if raw == "" {
					continue
				}
				if v, changedURL := remapLoopbackURL(raw); changedURL {
					p.Config[k] = v
					changed = true
				}
			}
		}
	}
	return changed
}

func shouldRemapLoopback() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("DAST_LOCALHOST_REMAP"))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	if strings.TrimSpace(os.Getenv("DAST_ZAP_NO_LOCALHOST_REMAP")) == "1" {
		return false
	}
	// Auto-enable only in containers. Host-native worker should keep localhost untouched.
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func remapLoopbackURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return raw, false
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return raw, false
	}
	h := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return raw, false
	}
	if port := u.Port(); port != "" {
		u.Host = loopbackHostGateway + ":" + port
	} else {
		u.Host = loopbackHostGateway
	}
	return u.String(), true
}

func remapLoopbackRegex(raw string) (string, bool) {
	s := raw
	repl := strings.NewReplacer(
		`127\.0\.0\.1`, `host\.docker\.internal`,
		`localhost`, `host\.docker\.internal`,
		`::1`, `host\.docker\.internal`,
		"127.0.0.1", "host.docker.internal",
	)
	out := repl.Replace(s)
	return out, out != s
}

