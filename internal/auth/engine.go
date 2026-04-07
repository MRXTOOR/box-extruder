package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// Run executes provider chain: first successful Prepare + Verify wins.
func (e *Engine) Run(cfg *config.ScanAsCode) (*Result, error) {
	res := &Result{
		Context: model.ContextSnapshot{
			ContextID:     uuid.NewString(),
			CreatedAt:     time.Now().UTC(),
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

	for _, p := range cfg.Auth.Providers {
		res.Context.AuthProviderChain = append(res.Context.AuthProviderChain, p.ID)
		switch p.Type {
		case "header":
			name := p.Config["headerName"]
			if name == "" {
				name = "Authorization"
			}
			valRef := ""
			if p.SecretsRef != nil {
				valRef = p.SecretsRef["headerValue"]
			}
			val, err := config.ResolveSecretRef(valRef)
			if err != nil {
				continue
			}
			res.HeaderInject[name] = val
			evID := uuid.NewString()
			if p.Verification != nil && p.Verification.Type == "endpointCheck" {
				urlStr, _ := p.Verification.Details["url"].(string)
				exp := expectedStatusFromDetails(p.Verification.Details)
				req, err := http.NewRequest(http.MethodGet, urlStr, nil)
				if err != nil {
					ev := model.Evidence{
						EvidenceID: evID,
						Type:       model.EvidenceAuthVerification,
						StepType:   model.StepCrawl,
						ContextID:  res.Context.ContextID,
						Payload: model.AuthVerificationPayload{
							ProviderID: p.ID,
							CheckURL:   urlStr,
							ExpectedStatus: exp,
							Result:     model.AuthNotAuthenticated,
							Detail:     err.Error(),
						},
					}
					res.Evidence = append(res.Evidence, ev)
					res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
					continue
				}
				for k, v := range res.HeaderInject {
					req.Header.Set(k, v)
				}
				resp, err := e.HTTPClient.Do(req)
				actual := 0
				if resp != nil {
					actual = resp.StatusCode
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				authRes := model.AuthAuthenticated
				detail := "ok"
				if err != nil {
					authRes = model.AuthUncertain
					detail = err.Error()
				} else if actual != exp {
					authRes = model.AuthNotAuthenticated
					detail = fmt.Sprintf("expected status %d got %d", exp, actual)
				}
				res.Context.AuthVerification = authRes
				ev := model.Evidence{
					EvidenceID: evID,
					Type:       model.EvidenceAuthVerification,
					StepType:   model.StepCrawl,
					ContextID:  res.Context.ContextID,
					Payload: model.AuthVerificationPayload{
						ProviderID:     p.ID,
						CheckURL:       urlStr,
						ExpectedStatus: exp,
						ActualStatus:   actual,
						Result:         authRes,
						Detail:         detail,
					},
				}
				res.Evidence = append(res.Evidence, ev)
				res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
				if authRes == model.AuthAuthenticated {
					return res, nil
				}
			} else {
				res.Context.AuthVerification = model.AuthAuthenticated
				return res, nil
			}
		case "cookieJar":
			// Cookie string from env ref
			cookieVal := ""
			if p.SecretsRef != nil {
				var err error
				cookieVal, err = config.ResolveSecretRef(p.SecretsRef["cookie"])
				if err != nil {
					continue
				}
			}
			res.CookieHeader = cookieVal
			res.HeaderInject["Cookie"] = strings.TrimSpace(res.HeaderInject["Cookie"] + "; " + cookieVal)
			res.Context.AuthVerification = model.AuthAuthenticated
			return res, nil
		case "juiceShopLogin":
			// OWASP Juice Shop (bkimminich/juice-shop): POST /rest/user/login JSON {email,password} → JWT; use Bearer for API.
			if len(cfg.Targets) == 0 || p.SecretsRef == nil {
				continue
			}
			email, err := config.ResolveSecretRef(p.SecretsRef["email"])
			if err != nil || email == "" {
				continue
			}
			password, err := config.ResolveSecretRef(p.SecretsRef["password"])
			if err != nil || password == "" {
				continue
			}
			base := strings.TrimSuffix(cfg.Targets[0].BaseURL, "/")
			loginPath := p.Config["loginPath"]
			if loginPath == "" {
				loginPath = "/rest/user/login"
			}
			if !strings.HasPrefix(loginPath, "/") {
				loginPath = "/" + loginPath
			}
			verifyPath := p.Config["verifyPath"]
			if verifyPath == "" {
				verifyPath = "/rest/user/whoami"
			}
			if !strings.HasPrefix(verifyPath, "/") {
				verifyPath = "/" + verifyPath
			}
			loginURL := base + loginPath
			bodyObj := map[string]string{"email": email, "password": password}
			bodyJSON, err := json.Marshal(bodyObj)
			if err != nil {
				continue
			}
			req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(bodyJSON))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := e.HTTPClient.Do(req)
			if err != nil {
				continue
			}
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var loginPayload struct {
				Authentication struct {
					Token string `json:"token"`
				} `json:"authentication"`
			}
			_ = json.Unmarshal(bodyBytes, &loginPayload)
			token := strings.TrimSpace(loginPayload.Authentication.Token)
			evID := uuid.NewString()
			if resp.StatusCode != http.StatusOK || token == "" {
				detail := fmt.Sprintf("login status %d, token empty=%v", resp.StatusCode, token == "")
				res.Context.AuthVerification = model.AuthNotAuthenticated
				ev := model.Evidence{
					EvidenceID: evID,
					Type:       model.EvidenceAuthVerification,
					StepType:   model.StepCrawl,
					ContextID:  res.Context.ContextID,
					Payload: model.AuthVerificationPayload{
						ProviderID: p.ID,
						CheckURL:   loginURL,
						Result:     model.AuthNotAuthenticated,
						Detail:     detail,
					},
				}
				res.Evidence = append(res.Evidence, ev)
				res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
				continue
			}
			bearer := "Bearer " + token
			res.HeaderInject["Authorization"] = bearer
			verifyURL := base + verifyPath
			vreq, err := http.NewRequest(http.MethodGet, verifyURL, nil)
			if err != nil {
				continue
			}
			vreq.Header.Set("Authorization", bearer)
			vresp, err := e.HTTPClient.Do(vreq)
			actual := 0
			if vresp != nil {
				actual = vresp.StatusCode
				io.Copy(io.Discard, vresp.Body)
				vresp.Body.Close()
			}
			exp := http.StatusOK
			authRes := model.AuthAuthenticated
			detail := "ok"
			if err != nil {
				authRes = model.AuthUncertain
				detail = err.Error()
			} else if actual != exp {
				authRes = model.AuthNotAuthenticated
				detail = fmt.Sprintf("whoami expected status %d got %d", exp, actual)
			}
			res.Context.AuthVerification = authRes
			ev := model.Evidence{
				EvidenceID: evID,
				Type:       model.EvidenceAuthVerification,
				StepType:   model.StepCrawl,
				ContextID:  res.Context.ContextID,
				Payload: model.AuthVerificationPayload{
					ProviderID:     p.ID,
					CheckURL:       verifyURL,
					ExpectedStatus: exp,
					ActualStatus:   actual,
					Result:         authRes,
					Detail:         detail,
				},
			}
			res.Evidence = append(res.Evidence, ev)
			res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
			if authRes == model.AuthAuthenticated {
				return res, nil
			}
		case "genericLogin":
			if p.GenericLogin == nil || strings.TrimSpace(p.GenericLogin.LoginURL) == "" || strings.TrimSpace(p.GenericLogin.VerifyURL) == "" {
				continue
			}
			if p.SecretsRef == nil {
				continue
			}
			loginCfg := p.GenericLogin
			loginMethod := strings.ToUpper(strings.TrimSpace(loginCfg.LoginMethod))
			if loginMethod == "" {
				loginMethod = http.MethodPost
			}
			contentType := strings.TrimSpace(loginCfg.ContentType)
			if contentType == "" {
				contentType = "application/json"
			}
			credMap := loginCfg.CredentialFields
			if len(credMap) == 0 {
				credMap = map[string]string{"email": "email", "login": "login", "username": "username", "password": "password"}
			}
			reqFields := map[string]string{}
			for secretKey, fieldName := range credMap {
				secretRef := strings.TrimSpace(p.SecretsRef[secretKey])
				if secretRef == "" {
					continue
				}
				val, err := config.ResolveSecretRef(secretRef)
				if err != nil || strings.TrimSpace(val) == "" {
					continue
				}
				fn := strings.TrimSpace(fieldName)
				if fn == "" {
					fn = secretKey
				}
				reqFields[fn] = val
			}
			for k, v := range loginCfg.StaticFields {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				reqFields[k] = v
			}
			if len(reqFields) == 0 {
				continue
			}
			var reqBody io.Reader
			switch contentType {
			case "application/x-www-form-urlencoded":
				f := url.Values{}
				for k, v := range reqFields {
					f.Set(k, v)
				}
				reqBody = strings.NewReader(f.Encode())
			default:
				bodyJSON, err := json.Marshal(reqFields)
				if err != nil {
					continue
				}
				reqBody = bytes.NewReader(bodyJSON)
				contentType = "application/json"
			}
			lreq, err := http.NewRequest(loginMethod, strings.TrimSpace(loginCfg.LoginURL), reqBody)
			if err != nil {
				continue
			}
			lreq.Header.Set("Content-Type", contentType)
			lresp, err := e.HTTPClient.Do(lreq)
			if err != nil || lresp == nil {
				continue
			}
			lb, _ := io.ReadAll(lresp.Body)
			lresp.Body.Close()
			evID := uuid.NewString()
			if lresp.StatusCode < 200 || lresp.StatusCode >= 300 {
				detail := fmt.Sprintf("login status %d", lresp.StatusCode)
				res.Context.AuthVerification = model.AuthNotAuthenticated
				ev := model.Evidence{
					EvidenceID: evID,
					Type:       model.EvidenceAuthVerification,
					StepType:   model.StepCrawl,
					ContextID:  res.Context.ContextID,
					Payload: model.AuthVerificationPayload{
						ProviderID: p.ID,
						CheckURL:   strings.TrimSpace(loginCfg.LoginURL),
						Result:     model.AuthNotAuthenticated,
						Detail:     detail,
					},
				}
				res.Evidence = append(res.Evidence, ev)
				res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
				continue
			}

			token := strings.TrimSpace(extractJSONToken(lb, loginCfg.TokenPath, loginCfg.TokenPaths))
			if token != "" {
				headerName := strings.TrimSpace(loginCfg.TokenHeaderName)
				if headerName == "" {
					headerName = "Authorization"
				}
				tokenType := strings.TrimSpace(loginCfg.TokenType)
				if tokenType == "" {
					tokenType = "Bearer"
				}
				res.HeaderInject[headerName] = strings.TrimSpace(tokenType + " " + token)
			}
			if loginCfg.UseCookies || token == "" {
				cookies := collectSetCookieHeader(lresp)
				if cookies != "" {
					res.CookieHeader = cookies
					res.HeaderInject["Cookie"] = strings.TrimSpace(strings.TrimSpace(res.HeaderInject["Cookie"]+"; ") + cookies)
				}
			}

			vmethod := strings.ToUpper(strings.TrimSpace(loginCfg.VerifyMethod))
			if vmethod == "" {
				vmethod = http.MethodGet
			}
			vreq, err := http.NewRequest(vmethod, strings.TrimSpace(loginCfg.VerifyURL), nil)
			if err != nil {
				continue
			}
			for k, v := range res.HeaderInject {
				if strings.TrimSpace(v) != "" {
					vreq.Header.Set(k, v)
				}
			}
			vresp, err := e.HTTPClient.Do(vreq)
			actual := 0
			if vresp != nil {
				actual = vresp.StatusCode
				io.Copy(io.Discard, vresp.Body)
				vresp.Body.Close()
			}
			exp := loginCfg.VerifyExpectedStatus
			if exp == 0 {
				exp = http.StatusOK
			}
			authRes := model.AuthAuthenticated
			detail := "ok"
			if err != nil {
				authRes = model.AuthUncertain
				detail = err.Error()
			} else if actual != exp {
				authRes = model.AuthNotAuthenticated
				detail = fmt.Sprintf("verify expected status %d got %d", exp, actual)
			}
			res.Context.AuthVerification = authRes
			ev := model.Evidence{
				EvidenceID: evID,
				Type:       model.EvidenceAuthVerification,
				StepType:   model.StepCrawl,
				ContextID:  res.Context.ContextID,
				Payload: model.AuthVerificationPayload{
					ProviderID:     p.ID,
					CheckURL:       strings.TrimSpace(loginCfg.VerifyURL),
					ExpectedStatus: exp,
					ActualStatus:   actual,
					Result:         authRes,
					Detail:         detail,
				},
			}
			res.Evidence = append(res.Evidence, ev)
			res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
			if authRes == model.AuthAuthenticated {
				return res, nil
			}
		case "oidcClientCredentials":
			// Generic OIDC/OAuth2 client-credentials flow:
			// 1) discovery document (optional) -> token endpoint
			// 2) POST token request (grant_type=client_credentials)
			// 3) optional verify endpoint check with Bearer token
			tokenEndpoint := strings.TrimSpace(p.Config["tokenEndpoint"])
			issuer := strings.TrimSpace(p.Config["issuer"])
			if tokenEndpoint == "" && issuer == "" {
				continue
			}
			clientID, err := config.ResolveSecretRef(p.SecretsRef["clientId"])
			if err != nil || strings.TrimSpace(clientID) == "" {
				continue
			}
			clientSecret, err := config.ResolveSecretRef(p.SecretsRef["clientSecret"])
			if err != nil || strings.TrimSpace(clientSecret) == "" {
				continue
			}
			if tokenEndpoint == "" {
				iss := strings.TrimRight(issuer, "/")
				discoveryURL := iss + "/.well-known/openid-configuration"
				dreq, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
				if err != nil {
					continue
				}
				dresp, err := e.HTTPClient.Do(dreq)
				if err != nil || dresp == nil {
					continue
				}
				db, _ := io.ReadAll(dresp.Body)
				dresp.Body.Close()
				if dresp.StatusCode != http.StatusOK {
					continue
				}
				var disc struct {
					TokenEndpoint string `json:"token_endpoint"`
				}
				if err := json.Unmarshal(db, &disc); err != nil || strings.TrimSpace(disc.TokenEndpoint) == "" {
					continue
				}
				tokenEndpoint = strings.TrimSpace(disc.TokenEndpoint)
			}

			form := url.Values{}
			form.Set("grant_type", "client_credentials")
			if scope := strings.TrimSpace(p.Config["scope"]); scope != "" {
				form.Set("scope", scope)
			}
			treq, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
			if err != nil {
				continue
			}
			treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			treq.SetBasicAuth(clientID, clientSecret)
			tresp, err := e.HTTPClient.Do(treq)
			if err != nil || tresp == nil {
				continue
			}
			tb, _ := io.ReadAll(tresp.Body)
			tresp.Body.Close()
			var tokenPayload struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
			}
			_ = json.Unmarshal(tb, &tokenPayload)
			token := strings.TrimSpace(tokenPayload.AccessToken)
			evID := uuid.NewString()
			if tresp.StatusCode != http.StatusOK || token == "" {
				detail := fmt.Sprintf("token status %d, access_token empty=%v", tresp.StatusCode, token == "")
				res.Context.AuthVerification = model.AuthNotAuthenticated
				ev := model.Evidence{
					EvidenceID: evID,
					Type:       model.EvidenceAuthVerification,
					StepType:   model.StepCrawl,
					ContextID:  res.Context.ContextID,
					Payload: model.AuthVerificationPayload{
						ProviderID: p.ID,
						CheckURL:   tokenEndpoint,
						Result:     model.AuthNotAuthenticated,
						Detail:     detail,
					},
				}
				res.Evidence = append(res.Evidence, ev)
				res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
				continue
			}
			bearer := "Bearer " + token
			res.HeaderInject["Authorization"] = bearer

			verifyURL := strings.TrimSpace(p.Config["verifyUrl"])
			if verifyURL == "" {
				// OIDC default for identity/user claims
				if issuer != "" {
					verifyURL = strings.TrimRight(issuer, "/") + "/userinfo"
				} else {
					// no explicit verification endpoint -> treat token obtain success as authenticated
					res.Context.AuthVerification = model.AuthAuthenticated
					return res, nil
				}
			}
			vreq, err := http.NewRequest(http.MethodGet, verifyURL, nil)
			if err != nil {
				continue
			}
			vreq.Header.Set("Authorization", bearer)
			vresp, err := e.HTTPClient.Do(vreq)
			actual := 0
			if vresp != nil {
				actual = vresp.StatusCode
				io.Copy(io.Discard, vresp.Body)
				vresp.Body.Close()
			}
			exp := expectedStatusFromDetails(map[string]any{"expectedStatus": p.Config["verifyExpectedStatus"]})
			if exp == 0 {
				exp = http.StatusOK
			}
			authRes := model.AuthAuthenticated
			detail := "ok"
			if err != nil {
				authRes = model.AuthUncertain
				detail = err.Error()
			} else if actual != exp {
				authRes = model.AuthNotAuthenticated
				detail = fmt.Sprintf("verify expected status %d got %d", exp, actual)
			}
			res.Context.AuthVerification = authRes
			ev := model.Evidence{
				EvidenceID: evID,
				Type:       model.EvidenceAuthVerification,
				StepType:   model.StepCrawl,
				ContextID:  res.Context.ContextID,
				Payload: model.AuthVerificationPayload{
					ProviderID:     p.ID,
					CheckURL:       verifyURL,
					ExpectedStatus: exp,
					ActualStatus:   actual,
					Result:         authRes,
					Detail:         detail,
				},
			}
			res.Evidence = append(res.Evidence, ev)
			res.Context.AuthEvidenceRefs = append(res.Context.AuthEvidenceRefs, evID)
			if authRes == model.AuthAuthenticated {
				return res, nil
			}
		default:
			continue
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
