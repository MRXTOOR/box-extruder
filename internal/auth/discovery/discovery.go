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
	TargetURL          string `json:"targetUrl"`
	AuthURL            string `json:"authUrl,omitempty"`
	VerifyURL          string `json:"verifyUrl,omitempty"`
	Login              string `json:"login"`
	Password           string `json:"password"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
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
	client := &http.Client{Timeout: 15 * time.Second}
	if req.InsecureSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	out := Result{
		InteractiveInputs: []config.AuthInteractiveInput{
			{Name: "username", Prompt: "Username / Email", Required: true},
			{Name: "password", Prompt: "Password", Required: true, Sensitive: true},
		},
	}
	base, err := normalizeBase(req.TargetURL)
	if err != nil {
		out.Error = "invalid targetUrl"
		return out
	}
	if strings.TrimSpace(req.Login) == "" || strings.TrimSpace(req.Password) == "" {
		out.Error = "login and password required"
		return out
	}

	loginURLs := candidateLoginURLs(base, req.AuthURL)
	verifyURLs := candidateVerifyURLs(base, req.VerifyURL)
	contentTypes := []string{"application/json", "application/x-www-form-urlencoded"}
	userFields := []string{"email", "username", "login", "user", "identifier"}
	passFields := []string{"password", "pass", "pwd"}

	for _, loginURL := range loginURLs {
		for _, ct := range contentTypes {
			for _, uf := range userFields {
				for _, pf := range passFields {
					authHeader, cookieHeader, ok, trace := tryLogin(client, loginURL, ct, uf, pf, req.Login, req.Password)
					out.Trace = append(out.Trace, trace...)
					if !ok {
						continue
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
							gl := &config.GenericLoginConfig{
								LoginURL:             loginURL,
								LoginMethod:          http.MethodPost,
								ContentType:          ct,
								CredentialFields:     map[string]string{"username": uf, "password": pf},
								TokenType:            "Bearer",
								TokenHeaderName:      "Authorization",
								VerifyURL:            vURL,
								VerifyMethod:         http.MethodGet,
								VerifyExpectedStatus: http.StatusOK,
							}
							if authHeader == "" {
								gl.UseCookies = true
							} else {
								gl.TokenPath = "access_token"
							}
							out.Verified = true
							out.VerifyURL = vURL
							out.VerifyStatus = status
							out.GenericLogin = gl
							out.Trace = dedupeTrace(out.Trace)
							return out
						}
					}
				}
			}
		}
	}
	out.Error = "unable to auto-discover auth flow"
	out.Trace = dedupeTrace(out.Trace)
	return out
}

// dedupeTrace убирает повторяющиеся шаги (одинаковый stage+url+method+detail).
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

func tryLogin(client *http.Client, loginURL, contentType, userField, passField, login, password string) (string, string, bool, []TraceStep) {
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
		return "", "", false, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: err.Error(), Success: false}}
	}
	r.Header.Set("Content-Type", contentType)
	resp, err := client.Do(r)
	if err != nil || resp == nil {
		msg := "request failed"
		if err != nil {
			msg = err.Error()
		}
		return "", "", false, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: msg, Success: false}}
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: fmt.Sprintf("status=%d", resp.StatusCode), Success: false}}
	}
	token := extractToken(data)
	authHeader := ""
	if token != "" {
		authHeader = "Bearer " + token
	}
	cookieHeader := collectSetCookieHeader(resp)
	ok := authHeader != "" || cookieHeader != ""
	detail := fmt.Sprintf("status=%d token=%v cookie=%v", resp.StatusCode, authHeader != "", cookieHeader != "")
	return authHeader, cookieHeader, ok, []TraceStep{{Stage: "login", URL: loginURL, Method: http.MethodPost, Detail: detail, Success: ok}}
}

func tryVerify(client *http.Client, verifyURL, authHeader, cookieHeader string) (int, error) {
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
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func candidateLoginURLs(base, authURL string) []string {
	if strings.TrimSpace(authURL) != "" {
		return []string{strings.TrimSpace(authURL)}
	}
	return []string{
		base + "/api/auth/login",
		base + "/auth/login",
		base + "/api/login",
		base + "/login",
		base + "/api/v1/auth/login",
	}
}

func candidateVerifyURLs(base, verifyURL string) []string {
	if strings.TrimSpace(verifyURL) != "" {
		return []string{strings.TrimSpace(verifyURL)}
	}
	return []string{
		base + "/api/me",
		base + "/me",
		base + "/userinfo",
		base + "/profile",
		base + "/api/v1/profile",
	}
}

func normalizeBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func extractToken(data []byte) string {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	for _, p := range []string{"access_token", "token", "data.token", "authentication.token"} {
		if v := dig(m, p); v != "" {
			return v
		}
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
