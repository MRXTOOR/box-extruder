package auth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/google/uuid"
)

// Engine prepares and verifies auth per provider chain.
type Engine struct {
	HTTPClient *http.Client
}

// NewEngine returns engine with timeout client.
func NewEngine() *Engine {
	return &Engine{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Result of auth phase.
type Result struct {
	Context      model.ContextSnapshot
	HeaderInject map[string]string // applied to subsequent workers
	CookieHeader string
	Evidence     []model.Evidence
}

// Run executes the provider chain: the first provider that authenticates wins.
func (e *Engine) Run(cfg *config.ScanAsCode) (*Result, error) {
	res := &Result{
		Context: model.ContextSnapshot{
			ContextID:        uuid.NewString(),
			CreatedAt:        time.Now().UTC(),
			AuthVerification: model.AuthUncertain,
		},
		HeaderInject: map[string]string{},
	}
	for _, t := range cfg.Targets {
		res.Context.TargetBaseURLs = append(res.Context.TargetBaseURLs, t.BaseURL)
	}
	res.Context.ScopeAllow = append(res.Context.ScopeAllow, cfg.Scope.Allow...)
	res.Context.ScopeDeny = append(res.Context.ScopeDeny, cfg.Scope.Deny...)
	if cfg.Scope.MaxURLs > 0 {
		res.Context.MaxURLs = cfg.Scope.MaxURLs
	}
	if cfg.Auth == nil || cfg.Auth.Strategy == "none" || len(cfg.Auth.Providers) == 0 {
		res.Context.AuthVerification = model.AuthAuthenticated
		return res, nil
	}

	if cfg.InsecureSkipTLSVerify {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		e.HTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}

	for _, p := range cfg.Auth.Providers {
		res.Context.AuthProviderChain = append(res.Context.AuthProviderChain, p.ID)
		var done bool
		switch p.Type {
		case "header":
			done = e.runHeaderProvider(res, p)
		case "cookieJar":
			done = e.runCookieJarProvider(res, p)
		case "juiceShopLogin":
			done = e.runJuiceShopProvider(res, p, cfg)
		case "genericLogin":
			done = e.runGenericLoginProvider(res, p)
		case "oidcClientCredentials":
			done = e.runOIDCClientCredentialsProvider(res, p)
		default:
			continue
		}
		if done {
			return res, nil
		}
	}

	res.Context.AuthVerification = model.AuthNotAuthenticated
	return res, nil
}

func expectedStatusFromDetails(d map[string]any) int {
	if d == nil {
		return 200
	}
	switch v := d["expectedStatus"].(type) {
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil && n > 0 {
			return n
		}
		return 200
	case int:
		if v == 0 {
			return 200
		}
		return v
	case int64:
		if v == 0 {
			return 200
		}
		return int(v)
	case float64:
		if v == 0 {
			return 200
		}
		return int(v)
	default:
		return 200
	}
}

func extractJSONToken(body []byte, primary string, fallbacks []string) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	paths := make([]string, 0, len(fallbacks)+5)
	if strings.TrimSpace(primary) != "" {
		paths = append(paths, strings.TrimSpace(primary))
	}
	paths = append(paths, fallbacks...)
	paths = append(paths, "access_token", "token", "data.token", "authentication.token")
	for _, p := range paths {
		if v := strings.TrimSpace(digStringPath(payload, p)); v != "" {
			return v
		}
	}
	return ""
}

func digStringPath(payload map[string]any, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	var cur any = payload
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[strings.TrimSpace(seg)]
		if !ok {
			return ""
		}
	}
	s, _ := cur.(string)
	return s
}

func collectSetCookieHeader(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return ""
	}
	var parts []string
	for _, c := range cookies {
		if strings.TrimSpace(c.Name) == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}
