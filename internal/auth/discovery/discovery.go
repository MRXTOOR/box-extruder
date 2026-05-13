package discovery

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/config"
)

type Request struct {
	TargetURL string `json:"targetUrl"`
	AuthURL   string `json:"authUrl,omitempty"`
	VerifyURL string `json:"verifyUrl,omitempty"`
	Login     string `json:"login"`
	Password  string `json:"password"`
	// InsecureSkipTLSVerify mirrors curl --insecure for self-signed targets during discovery.
	InsecureSkipTLSVerify bool `json:"insecureSkipTlsVerify,omitempty"`
}

type TraceStep struct {
	Stage   string `json:"stage"`
	URL     string `json:"url,omitempty"`
	Method  string `json:"method,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Success bool   `json:"success"`
}

type Result struct {
	Verified          bool                          `json:"verified"`
	VerifyStatus      int                           `json:"verifyStatus,omitempty"`
	VerifyURL         string                        `json:"verifyUrl,omitempty"`
	GenericLogin      *config.GenericLoginConfig    `json:"genericLogin,omitempty"`
	InteractiveInputs []config.AuthInteractiveInput `json:"interactiveInputs,omitempty"`
	Trace             []TraceStep                   `json:"trace"`
	Error             string                        `json:"error,omitempty"`
}

func Discover(req Request) Result {
	out := Result{
		InteractiveInputs: []config.AuthInteractiveInput{
			{Name: "username", Prompt: "Username / Email", Required: true},
			{Name: "password", Prompt: "Password", Required: true, Sensitive: true},
		},
	}
	client := newHTTPClient(req.InsecureSkipTLSVerify)

	_, err := normalizeBase(req.TargetURL)
	if err != nil {
		out.Error = "invalid targetUrl"
		return out
	}
	if strings.TrimSpace(req.Login) == "" || strings.TrimSpace(req.Password) == "" {
		out.Error = "login and password required"
		return out
	}
	loginURL := strings.TrimSpace(req.AuthURL)
	if loginURL == "" {
		out.Error = "authUrl is required: enter the full login endpoint URL (URL auto-discovery was removed)"
		return out
	}

	verifyURLs := candidateVerifyURLs(strings.TrimSpace(req.VerifyURL))
	contentTypes := []string{"application/json", "application/x-www-form-urlencoded"}
	userFields := []string{"email", "username", "login", "user", "identifier", "phone", "mobile"}
	passFields := []string{"password", "pass", "pwd"}

	for _, ct := range contentTypes {
		for _, uf := range userFields {
			for _, pf := range passFields {
				authHeader, cookieHeader, body, ok, trace := tryLogin(client, loginURL, ct, uf, pf, req.Login, req.Password)
				out.Trace = append(out.Trace, trace...)
				if !ok {
					continue
				}
				tokenPath, _, tokenType := extractTokenWithPath(body)
				glBase := &config.GenericLoginConfig{
					LoginURL:             loginURL,
					LoginMethod:          http.MethodPost,
					ContentType:          ct,
					CredentialFields:     map[string]string{"username": uf, "password": pf},
					TokenHeaderName:      "Authorization",
					VerifyMethod:         http.MethodGet,
					VerifyExpectedStatus: http.StatusOK,
				}
				if authHeader == "" {
					glBase.UseCookies = true
				} else {
					glBase.TokenPath = tokenPath
					if tt := strings.TrimSpace(tokenType); tt != "" {
						glBase.TokenType = normalizeTokenType(tt)
					} else {
						glBase.TokenType = "Bearer"
					}
				}

				if len(verifyURLs) == 0 {
					if authHeader == "" && cookieHeader == "" {
						continue
					}
					out.Verified = true
					out.GenericLogin = glBase
					out.Trace = dedupeTrace(out.Trace)
					return out
				}

				for _, vURL := range verifyURLs {
					status, verr := tryVerify(client, vURL, authHeader, cookieHeader)
					step := TraceStep{
						Stage:   "verify",
						URL:     vURL,
						Method:  http.MethodGet,
						Detail:  fmt.Sprintf("status=%d", status),
						Success: verr == nil && status == http.StatusOK,
					}
					if verr != nil {
						step.Detail = verr.Error()
					}
					out.Trace = append(out.Trace, step)
					if verr == nil && status == http.StatusOK {
						gl := *glBase
						gl.VerifyURL = vURL
						out.Verified = true
						out.VerifyURL = vURL
						out.VerifyStatus = status
						out.GenericLogin = &gl
						out.Trace = dedupeTrace(out.Trace)
						return out
					}
				}
			}
		}
	}
	out.Error = "unable to complete auth with the given authUrl (check credentials, content type, field names, or set verifyUrl)"
	out.Trace = dedupeTrace(out.Trace)
	return out
}

func newHTTPClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func normalizeTokenType(tt string) string {
	tt = strings.TrimSpace(tt)
	if tt == "" {
		return "Bearer"
	}
	// JSON token_type is often "Bearer"; header uses same word without duplication in engine.
	if strings.EqualFold(tt, "bearer") {
		return "Bearer"
	}
	return tt
}

func dedupeTrace(steps []TraceStep) []TraceStep {
	seen := make(map[string]struct{})
	out := make([]TraceStep, 0, len(steps))
	for _, s := range steps {
		key := s.Stage + "|" + s.URL + "|" + s.Method + "|" + s.Detail + "|" + fmt.Sprint(s.Success)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

// tryLogin returns auth Bearer header (if JSON token found), Set-Cookie aggregate, response body on 2xx.
func tryLogin(client *http.Client, loginURL, contentType, userField, passField, login, password string) (string, string, []byte, bool, []TraceStep) {
	reqFields := map[string]string{userField: login, passField: password}
	var body io.Reader
	switch contentType {
	case "application/x-www-form-urlencoded":
		f := url.Values{}
		for k, v := range reqFields {
			f.Set(k, v)
		}
		body = strings.NewReader(f.Encode())
	default:
		b, _ := json.Marshal(reqFields)
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequest(http.MethodPost, loginURL, body)
	if err != nil {
		return "", "", nil, false, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: err.Error(), Success: false}}
	}
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("User-Agent", "AppSec-DAST-auth-discovery/1.0")
	resp, err := client.Do(r)
	if err != nil || resp == nil {
		msg := "request failed"
		if err != nil {
			msg = err.Error()
		}
		return "", "", nil, false, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: msg, Success: false}}
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", nil, false, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: fmt.Sprintf("status=%d", resp.StatusCode), Success: false}}
	}
	tokenPath, token, tokenType := extractTokenWithPath(data)
	authHeader := ""
	if token != "" {
		tt := strings.TrimSpace(tokenType)
		if tt == "" || strings.EqualFold(tt, "bearer") {
			authHeader = "Bearer " + token
		} else {
			authHeader = strings.TrimSpace(tt + " " + token)
		}
	}
	cookieHeader := collectSetCookieHeader(resp)
	ok := authHeader != "" || cookieHeader != ""
	detail := fmt.Sprintf("status=%d token=%v cookie=%v path=%q", resp.StatusCode, authHeader != "", cookieHeader != "", tokenPath)
	return authHeader, cookieHeader, data, ok, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: detail, Success: ok}}
}

func tryVerify(client *http.Client, verifyURL, authHeader, cookieHeader string) (int, error) {
	if strings.TrimSpace(verifyURL) == "" {
		return 0, fmt.Errorf("empty verify url")
	}
	req, err := http.NewRequest(http.MethodGet, verifyURL, nil)
	if err != nil {
		return 0, err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	req.Header.Set("User-Agent", "AppSec-DAST-auth-discovery/1.0")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// candidateVerifyURLs returns explicit verify URL only; empty input means caller skips HTTP verify after login.
func candidateVerifyURLs(verifyURL string) []string {
	if strings.TrimSpace(verifyURL) == "" {
		return nil
	}
	return []string{strings.TrimSpace(verifyURL)}
}

func normalizeBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func extractTokenWithPath(data []byte) (path string, token string, tokenType string) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return "", "", ""
	}
	tokenType = readTokenType(m)
	candidates := []string{
		"access_token", "accessToken", "id_token", "idToken",
		"data.access_token", "data.accessToken", "data.token",
		"token", "authentication.token", "jwt", "result.token",
		"result.access_token", "credentials.accessToken", "auth.token",
	}
	for _, p := range candidates {
		if v := dig(m, p); v != "" && !strings.Contains(strings.ToLower(p), "refresh") {
			return p, v, tokenType
		}
	}
	for k, v := range m {
		lk := strings.ToLower(strings.TrimSpace(k))
		if strings.Contains(lk, "refresh") {
			continue
		}
		if !(strings.Contains(lk, "token") || lk == "jwt") {
			continue
		}
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return k, strings.TrimSpace(s), tokenType
		}
	}
	return "", "", tokenType
}

func readTokenType(m map[string]any) string {
	if m == nil {
		return ""
	}
	if s, ok := m["token_type"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	return ""
}

func dig(m map[string]any, path string) string {
	cur := any(m)
	for _, seg := range strings.Split(path, ".") {
		node, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = node[seg]
		if !ok {
			return ""
		}
	}
	s, _ := cur.(string)
	return strings.TrimSpace(s)
}

func collectSetCookieHeader(resp *http.Response) string {
	var parts []string
	for _, c := range resp.Cookies() {
		if strings.TrimSpace(c.Name) == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}
