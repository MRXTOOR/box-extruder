package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/google/uuid"
)

// Each runXxxProvider method attempts one auth strategy. It records evidence on
// res and returns true only when authentication succeeded and the provider
// chain should short-circuit; returning false lets Run try the next provider.

func (e *Engine) runHeaderProvider(res *Result, p config.AuthProvider) bool {
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
		return false
	}
	res.HeaderInject[name] = val
	evID := uuid.NewString()

	if p.Verification == nil || p.Verification.Type != "endpointCheck" {
		res.Context.AuthVerification = model.AuthAuthenticated
		return true
	}

	urlStr, _ := p.Verification.Details["url"].(string)
	exp := expectedStatusFromDetails(p.Verification.Details)
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		res.appendAuthEvidence(evID, model.AuthVerificationPayload{
			ProviderID:     p.ID,
			CheckURL:       urlStr,
			ExpectedStatus: exp,
			Result:         model.AuthNotAuthenticated,
			Detail:         err.Error(),
		})
		return false
	}
	for k, v := range res.HeaderInject {
		req.Header.Set(k, v)
	}
	resp, err := e.HTTPClient.Do(req)
	actual := drainStatus(resp)
	authRes, detail := classifyStatus(err, actual, exp)
	res.Context.AuthVerification = authRes
	res.appendAuthEvidence(evID, model.AuthVerificationPayload{
		ProviderID:     p.ID,
		CheckURL:       urlStr,
		ExpectedStatus: exp,
		ActualStatus:   actual,
		Result:         authRes,
		Detail:         detail,
	})
	return authRes == model.AuthAuthenticated
}

func (e *Engine) runCookieJarProvider(res *Result, p config.AuthProvider) bool {
	cookieVal := ""
	if p.SecretsRef != nil {
		var err error
		cookieVal, err = config.ResolveSecretRef(p.SecretsRef["cookie"])
		if err != nil {
			return false
		}
	}
	res.CookieHeader = cookieVal
	res.HeaderInject["Cookie"] = strings.TrimSpace(res.HeaderInject["Cookie"] + "; " + cookieVal)
	res.Context.AuthVerification = model.AuthAuthenticated
	return true
}

func (e *Engine) runJuiceShopProvider(res *Result, p config.AuthProvider, cfg *config.ScanAsCode) bool {
	// OWASP Juice Shop: POST /rest/user/login JSON {email,password} → JWT; use Bearer for API.
	if len(cfg.Targets) == 0 || p.SecretsRef == nil {
		return false
	}
	email, err := config.ResolveSecretRef(p.SecretsRef["email"])
	if err != nil || email == "" {
		return false
	}
	password, err := config.ResolveSecretRef(p.SecretsRef["password"])
	if err != nil || password == "" {
		return false
	}
	base := strings.TrimSuffix(cfg.Targets[0].BaseURL, "/")
	loginPath := normalizePath(p.Config["loginPath"], "/rest/user/login")
	verifyPath := normalizePath(p.Config["verifyPath"], "/rest/user/whoami")
	loginURL := base + loginPath

	bodyJSON, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		return false
	}
	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return false
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
		res.Context.AuthVerification = model.AuthNotAuthenticated
		res.appendAuthEvidence(evID, model.AuthVerificationPayload{
			ProviderID: p.ID,
			CheckURL:   loginURL,
			Result:     model.AuthNotAuthenticated,
			Detail:     fmt.Sprintf("login status %d, token empty=%v", resp.StatusCode, token == ""),
		})
		return false
	}

	bearer := "Bearer " + token
	res.HeaderInject["Authorization"] = bearer
	verifyURL := base + verifyPath
	vreq, err := http.NewRequest(http.MethodGet, verifyURL, nil)
	if err != nil {
		return false
	}
	vreq.Header.Set("Authorization", bearer)
	vresp, verr := e.HTTPClient.Do(vreq)
	actual := drainStatus(vresp)
	authRes, detail := classifyStatus(verr, actual, http.StatusOK)
	if verr == nil && actual != http.StatusOK {
		detail = fmt.Sprintf("whoami expected status %d got %d", http.StatusOK, actual)
	}
	res.Context.AuthVerification = authRes
	res.appendAuthEvidence(evID, model.AuthVerificationPayload{
		ProviderID:     p.ID,
		CheckURL:       verifyURL,
		ExpectedStatus: http.StatusOK,
		ActualStatus:   actual,
		Result:         authRes,
		Detail:         detail,
	})
	return authRes == model.AuthAuthenticated
}

func (e *Engine) runGenericLoginProvider(res *Result, p config.AuthProvider) bool {
	if p.GenericLogin == nil || strings.TrimSpace(p.GenericLogin.LoginURL) == "" || p.SecretsRef == nil {
		return false
	}
	loginCfg := p.GenericLogin
	loginMethod := defaultString(strings.ToUpper(strings.TrimSpace(loginCfg.LoginMethod)), http.MethodPost)
	contentType := defaultString(strings.TrimSpace(loginCfg.ContentType), "application/json")

	reqFields := genericLoginFields(p, loginCfg)
	if len(reqFields) == 0 {
		return false
	}
	reqBody, contentType, ok := genericLoginBody(reqFields, contentType)
	if !ok {
		return false
	}

	lreq, err := http.NewRequest(loginMethod, strings.TrimSpace(loginCfg.LoginURL), reqBody)
	if err != nil {
		return false
	}
	lreq.Header.Set("Content-Type", contentType)
	lresp, err := e.HTTPClient.Do(lreq)
	if err != nil || lresp == nil {
		return false
	}
	lb, _ := io.ReadAll(lresp.Body)
	lresp.Body.Close()
	evID := uuid.NewString()
	if lresp.StatusCode < 200 || lresp.StatusCode >= 300 {
		res.Context.AuthVerification = model.AuthNotAuthenticated
		res.appendAuthEvidence(evID, model.AuthVerificationPayload{
			ProviderID: p.ID,
			CheckURL:   strings.TrimSpace(loginCfg.LoginURL),
			Result:     model.AuthNotAuthenticated,
			Detail:     fmt.Sprintf("login status %d", lresp.StatusCode),
		})
		return false
	}

	token := applyLoginSession(res, lresp, lb, loginCfg)
	return e.verifyGenericLogin(res, p, loginCfg, evID, token)
}

// genericLoginFields resolves the credential and static form fields for a
// generic login request.
func genericLoginFields(p config.AuthProvider, loginCfg *config.GenericLoginConfig) map[string]string {
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
		if k = strings.TrimSpace(k); k != "" {
			reqFields[k] = v
		}
	}
	return reqFields
}

// genericLoginBody encodes the login fields per content type, returning ok=false
// when the body cannot be built.
func genericLoginBody(reqFields map[string]string, contentType string) (io.Reader, string, bool) {
	switch contentType {
	case "application/x-www-form-urlencoded":
		f := url.Values{}
		for k, v := range reqFields {
			f.Set(k, v)
		}
		return strings.NewReader(f.Encode()), contentType, true
	default:
		bodyJSON, err := json.Marshal(reqFields)
		if err != nil {
			return nil, "", false
		}
		return bytes.NewReader(bodyJSON), "application/json", true
	}
}

// applyLoginSession injects the bearer token and/or cookies from the login
// response into res and returns the extracted token (may be empty).
func applyLoginSession(res *Result, lresp *http.Response, lb []byte, loginCfg *config.GenericLoginConfig) string {
	token := strings.TrimSpace(extractJSONToken(lb, loginCfg.TokenPath, loginCfg.TokenPaths))
	if token != "" {
		headerName := defaultString(strings.TrimSpace(loginCfg.TokenHeaderName), "Authorization")
		tokenType := defaultString(strings.TrimSpace(loginCfg.TokenType), "Bearer")
		res.HeaderInject[headerName] = strings.TrimSpace(tokenType + " " + token)
	}
	if loginCfg.UseCookies || token == "" {
		if cookies := collectSetCookieHeader(lresp); cookies != "" {
			res.CookieHeader = cookies
			res.HeaderInject["Cookie"] = strings.TrimSpace(strings.TrimSpace(res.HeaderInject["Cookie"]+"; ") + cookies)
		}
	}
	return token
}

// verifyGenericLogin verifies the established session, either by trusting the
// login response (no verifyUrl) or by calling the configured verify endpoint.
func (e *Engine) verifyGenericLogin(res *Result, p config.AuthProvider, loginCfg *config.GenericLoginConfig, evID, token string) bool {
	if strings.TrimSpace(loginCfg.VerifyURL) == "" {
		hasSession := token != "" || strings.TrimSpace(res.HeaderInject["Cookie"]) != "" || strings.TrimSpace(res.CookieHeader) != ""
		authRes := model.AuthAuthenticated
		detail := "verifyUrl omitted: trusting login response (token or cookies)"
		if !hasSession {
			authRes = model.AuthNotAuthenticated
			detail = "verifyUrl omitted and login response had no token or Set-Cookie"
		}
		res.Context.AuthVerification = authRes
		res.appendAuthEvidence(evID, model.AuthVerificationPayload{
			ProviderID: p.ID,
			CheckURL:   strings.TrimSpace(loginCfg.LoginURL),
			Result:     authRes,
			Detail:     detail,
		})
		return authRes == model.AuthAuthenticated
	}

	vmethod := defaultString(strings.ToUpper(strings.TrimSpace(loginCfg.VerifyMethod)), http.MethodGet)
	vreq, err := http.NewRequest(vmethod, strings.TrimSpace(loginCfg.VerifyURL), nil)
	if err != nil {
		return false
	}
	for k, v := range res.HeaderInject {
		if strings.TrimSpace(v) != "" {
			vreq.Header.Set(k, v)
		}
	}
	vresp, verr := e.HTTPClient.Do(vreq)
	actual := drainStatus(vresp)
	exp := loginCfg.VerifyExpectedStatus
	if exp == 0 {
		exp = http.StatusOK
	}
	authRes, detail := classifyStatus(verr, actual, exp)
	if verr == nil && actual != exp {
		detail = fmt.Sprintf("verify expected status %d got %d", exp, actual)
	}
	res.Context.AuthVerification = authRes
	res.appendAuthEvidence(evID, model.AuthVerificationPayload{
		ProviderID:     p.ID,
		CheckURL:       strings.TrimSpace(loginCfg.VerifyURL),
		ExpectedStatus: exp,
		ActualStatus:   actual,
		Result:         authRes,
		Detail:         detail,
	})
	return authRes == model.AuthAuthenticated
}

// runOIDCClientCredentialsProvider runs a generic OIDC/OAuth2 client-credentials
// flow: optional discovery → token → optional verify.
func (e *Engine) runOIDCClientCredentialsProvider(res *Result, p config.AuthProvider) bool {
	evID := uuid.NewString()
	token, ok := e.oidcAcquireToken(res, p, evID)
	if !ok {
		return false
	}
	bearer := "Bearer " + token
	res.HeaderInject["Authorization"] = bearer
	return e.oidcVerifyToken(res, p, bearer, evID)
}

// oidcAcquireToken resolves the token endpoint (optionally via discovery) and
// performs the client-credentials grant, returning the access token.
func (e *Engine) oidcAcquireToken(res *Result, p config.AuthProvider, evID string) (string, bool) {
	tokenEndpoint := strings.TrimSpace(p.Config["tokenEndpoint"])
	issuer := strings.TrimSpace(p.Config["issuer"])
	if tokenEndpoint == "" && issuer == "" {
		return "", false
	}
	clientID, err := config.ResolveSecretRef(p.SecretsRef["clientId"])
	if err != nil || strings.TrimSpace(clientID) == "" {
		return "", false
	}
	clientSecret, err := config.ResolveSecretRef(p.SecretsRef["clientSecret"])
	if err != nil || strings.TrimSpace(clientSecret) == "" {
		return "", false
	}
	if tokenEndpoint == "" {
		tokenEndpoint = e.discoverTokenEndpoint(issuer)
		if tokenEndpoint == "" {
			return "", false
		}
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope := strings.TrimSpace(p.Config["scope"]); scope != "" {
		form.Set("scope", scope)
	}
	treq, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", false
	}
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	treq.SetBasicAuth(clientID, clientSecret)
	tresp, err := e.HTTPClient.Do(treq)
	if err != nil || tresp == nil {
		return "", false
	}
	tb, _ := io.ReadAll(tresp.Body)
	tresp.Body.Close()
	var tokenPayload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	_ = json.Unmarshal(tb, &tokenPayload)
	token := strings.TrimSpace(tokenPayload.AccessToken)
	if tresp.StatusCode != http.StatusOK || token == "" {
		res.Context.AuthVerification = model.AuthNotAuthenticated
		res.appendAuthEvidence(evID, model.AuthVerificationPayload{
			ProviderID: p.ID,
			CheckURL:   tokenEndpoint,
			Result:     model.AuthNotAuthenticated,
			Detail:     fmt.Sprintf("token status %d, access_token empty=%v", tresp.StatusCode, token == ""),
		})
		return "", false
	}
	return token, true
}

// oidcVerifyToken validates the bearer token against the verify/userinfo endpoint.
func (e *Engine) oidcVerifyToken(res *Result, p config.AuthProvider, bearer, evID string) bool {
	issuer := strings.TrimSpace(p.Config["issuer"])
	verifyURL := strings.TrimSpace(p.Config["verifyUrl"])
	if verifyURL == "" {
		if issuer == "" {
			// No verification endpoint: treat token acquisition as success.
			res.Context.AuthVerification = model.AuthAuthenticated
			return true
		}
		verifyURL = strings.TrimRight(issuer, "/") + "/userinfo"
	}
	vreq, err := http.NewRequest(http.MethodGet, verifyURL, nil)
	if err != nil {
		return false
	}
	vreq.Header.Set("Authorization", bearer)
	vresp, verr := e.HTTPClient.Do(vreq)
	actual := drainStatus(vresp)
	exp := expectedStatusFromDetails(map[string]any{"expectedStatus": p.Config["verifyExpectedStatus"]})
	if exp == 0 {
		exp = http.StatusOK
	}
	authRes, detail := classifyStatus(verr, actual, exp)
	if verr == nil && actual != exp {
		detail = fmt.Sprintf("verify expected status %d got %d", exp, actual)
	}
	res.Context.AuthVerification = authRes
	res.appendAuthEvidence(evID, model.AuthVerificationPayload{
		ProviderID:     p.ID,
		CheckURL:       verifyURL,
		ExpectedStatus: exp,
		ActualStatus:   actual,
		Result:         authRes,
		Detail:         detail,
	})
	return authRes == model.AuthAuthenticated
}

// discoverTokenEndpoint resolves token_endpoint from an OIDC discovery document.
func (e *Engine) discoverTokenEndpoint(issuer string) string {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	dreq, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
	if err != nil {
		return ""
	}
	dresp, err := e.HTTPClient.Do(dreq)
	if err != nil || dresp == nil {
		return ""
	}
	db, _ := io.ReadAll(dresp.Body)
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		return ""
	}
	var disc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(db, &disc); err != nil {
		return ""
	}
	return strings.TrimSpace(disc.TokenEndpoint)
}

// appendAuthEvidence records an auth-verification evidence entry on the result.
func (r *Result) appendAuthEvidence(evID string, payload model.AuthVerificationPayload) {
	r.Evidence = append(r.Evidence, model.Evidence{
		EvidenceID: evID,
		Type:       model.EvidenceAuthVerification,
		StepType:   model.StepCrawl,
		ContextID:  r.Context.ContextID,
		Payload:    payload,
	})
	r.Context.AuthEvidenceRefs = append(r.Context.AuthEvidenceRefs, evID)
}

// drainStatus returns the response status code (0 if resp is nil) and drains the body.
func drainStatus(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// classifyStatus maps a request error / actual vs expected status to an auth result.
func classifyStatus(err error, actual, expected int) (model.AuthVerificationResult, string) {
	switch {
	case err != nil:
		return model.AuthUncertain, err.Error()
	case actual != expected:
		return model.AuthNotAuthenticated, fmt.Sprintf("expected status %d got %d", expected, actual)
	default:
		return model.AuthAuthenticated, "ok"
	}
}

func normalizePath(p, fallback string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		p = fallback
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
