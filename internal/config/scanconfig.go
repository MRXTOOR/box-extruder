package config

// ScanAsCode root document (YAML/JSON).
type ScanAsCode struct {
	Version   string       `yaml:"version" json:"version"`
	Job       JobMeta      `yaml:"job" json:"job"`
	Targets   []Target     `yaml:"targets" json:"targets"`
	Scope     Scope        `yaml:"scope" json:"scope"`
	Auth      *Auth        `yaml:"auth,omitempty" json:"auth,omitempty"`
	Scan      Scan         `yaml:"scan" json:"scan"`
	Budgets   Budgets      `yaml:"budgets" json:"budgets"`
	Noise     NoiseControl `yaml:"noiseControl" json:"noiseControl"`
	Outputs   Outputs      `yaml:"outputs" json:"outputs"`
	Execution *Execution   `yaml:"execution,omitempty" json:"execution,omitempty"`
}

type JobMeta struct {
	Name string `yaml:"name" json:"name"`
	ID   string `yaml:"id,omitempty" json:"id,omitempty"`
}

type Target struct {
	Type        string   `yaml:"type" json:"type"`
	BaseURL     string   `yaml:"baseUrl" json:"baseUrl"`
	StartPoints []string `yaml:"startPoints,omitempty" json:"startPoints,omitempty"`
	ExcludeURLs []string `yaml:"excludeUrls,omitempty" json:"excludeUrls,omitempty"`
	IncludeURLs []string `yaml:"includeUrls,omitempty" json:"includeUrls,omitempty"`
}

type Scope struct {
	Allow   []string `yaml:"allow" json:"allow"`
	Deny    []string `yaml:"deny" json:"deny"`
	MaxURLs int      `yaml:"maxUrls,omitempty" json:"maxUrls,omitempty"`
}

type Auth struct {
	Strategy  string         `yaml:"strategy" json:"strategy"`
	Providers []AuthProvider `yaml:"providers,omitempty" json:"providers,omitempty"`
}

type AuthProvider struct {
	Type       string            `yaml:"type" json:"type"`
	ID         string            `yaml:"id" json:"id"`
	SecretsRef map[string]string `yaml:"secretsRef,omitempty" json:"secretsRef,omitempty"`
	Config     map[string]string `yaml:"config,omitempty" json:"config,omitempty"`
	// GenericLogin — универсальная схема логина (json/form/cookie + token extraction + verify).
	GenericLogin *GenericLoginConfig `yaml:"genericLogin,omitempty" json:"genericLogin,omitempty"`
	// InteractiveInputs — поля, которые CLI запрашивает у пользователя перед запуском.
	// Значения кладутся в secretsRef[input.name].
	InteractiveInputs []AuthInteractiveInput `yaml:"interactiveInputs,omitempty" json:"interactiveInputs,omitempty"`
	Verification      *AuthVerification      `yaml:"verification,omitempty" json:"verification,omitempty"`
}

type AuthVerification struct {
	Type    string         `yaml:"type" json:"type"`
	Details map[string]any `yaml:"details,omitempty" json:"details,omitempty"`
}

type AuthInteractiveInput struct {
	Name      string `yaml:"name" json:"name"`
	Prompt    string `yaml:"prompt,omitempty" json:"prompt,omitempty"`
	Sensitive bool   `yaml:"sensitive,omitempty" json:"sensitive,omitempty"`
	Required  bool   `yaml:"required,omitempty" json:"required,omitempty"`
}

// GenericLoginConfig describes universal auth flow without product-specific provider.
type GenericLoginConfig struct {
	LoginURL    string `yaml:"loginUrl" json:"loginUrl"`
	LoginMethod string `yaml:"loginMethod,omitempty" json:"loginMethod,omitempty"`
	ContentType string `yaml:"contentType,omitempty" json:"contentType,omitempty"` // application/json | application/x-www-form-urlencoded
	// CredentialFields maps secretsRef keys to request field names.
	// Example: {"email":"username","password":"password"}.
	CredentialFields map[string]string `yaml:"credentialFields,omitempty" json:"credentialFields,omitempty"`
	// StaticFields are sent as-is in login request body/form.
	StaticFields map[string]string `yaml:"staticFields,omitempty" json:"staticFields,omitempty"`

	// Token extraction and injection.
	TokenPath       string   `yaml:"tokenPath,omitempty" json:"tokenPath,omitempty"`             // dot-path, e.g. data.token
	TokenPaths      []string `yaml:"tokenPaths,omitempty" json:"tokenPaths,omitempty"`           // fallback list
	TokenType       string   `yaml:"tokenType,omitempty" json:"tokenType,omitempty"`             // default: Bearer
	TokenHeaderName string   `yaml:"tokenHeaderName,omitempty" json:"tokenHeaderName,omitempty"` // default: Authorization

	// Session verification.
	VerifyURL            string `yaml:"verifyUrl" json:"verifyUrl"`
	VerifyMethod         string `yaml:"verifyMethod,omitempty" json:"verifyMethod,omitempty"`                 // default: GET
	VerifyExpectedStatus int    `yaml:"verifyExpectedStatus,omitempty" json:"verifyExpectedStatus,omitempty"` // default: 200
	UseCookies           bool   `yaml:"useCookies,omitempty" json:"useCookies,omitempty"`                     // when true use Set-Cookie fallback
}

type Scan struct {
	Preset string     `yaml:"preset,omitempty" json:"preset,omitempty"`
	Plan   []ScanStep `yaml:"plan,omitempty" json:"plan,omitempty"`
}

type ScanStep struct {
	StepType string   `yaml:"stepType" json:"stepType"`
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Rules    []string `yaml:"rules,omitempty" json:"rules,omitempty"`
	// Nuclei-like: optional glob paths relative to workspace
	TemplatePaths []string `yaml:"templatePaths,omitempty" json:"templatePaths,omitempty"`
	// NucleiEngine: пусто или "builtin" — встроенный упрощённый движок; "cli" — бинарь nuclei (DAST_NUCLEI_BIN).
	NucleiEngine string `yaml:"nucleiEngine,omitempty" json:"nucleiEngine,omitempty"`
	// NucleiExtraArgs — дополнительные аргументы к nuclei (после наших -silent -jsonl -u -t …).
	NucleiExtraArgs []string `yaml:"nucleiExtraArgs,omitempty" json:"nucleiExtraArgs,omitempty"`
	NucleiRateLimit int      `yaml:"nucleiRateLimit,omitempty" json:"nucleiRateLimit,omitempty"`
	// NucleiIncludeDiscoveredURLs — добавить к целям Nuclei URL из предыдущих шагов Katana/ZAP (HTTP evidence).
	NucleiIncludeDiscoveredURLs bool `yaml:"nucleiIncludeDiscoveredURLs,omitempty" json:"nucleiIncludeDiscoveredURLs,omitempty"`
	// ZAP: optional docker image override
	ZAPDockerImage string `yaml:"zapDockerImage,omitempty" json:"zapDockerImage,omitempty"`
	// ZAP Automation Framework (zap.sh -autorun): spider + optional Ajax Spider, passive wait, JSON report.
	// Если true или включён zapSpiderAjax / задан zapAutomationFile — вместо zap-baseline.py.
	ZAPAutomationFramework bool `yaml:"zapAutomationFramework,omitempty" json:"zapAutomationFramework,omitempty"`
	ZAPSpiderTraditional   bool `yaml:"zapSpiderTraditional,omitempty" json:"zapSpiderTraditional,omitempty"` // default true при AF
	ZAPSpiderAjax          bool `yaml:"zapSpiderAjax,omitempty" json:"zapSpiderAjax,omitempty"`
	ZAPMaxSpiderMinutes    int  `yaml:"zapMaxSpiderMinutes,omitempty" json:"zapMaxSpiderMinutes,omitempty"`
	ZAPSpiderMaxDepth      int  `yaml:"zapSpiderMaxDepth,omitempty" json:"zapSpiderMaxDepth,omitempty"`
	ZAPSpiderMaxChildren   int  `yaml:"zapSpiderMaxChildren,omitempty" json:"zapSpiderMaxChildren,omitempty"`
	ZAPPassiveWaitSeconds  int  `yaml:"zapPassiveWaitSeconds,omitempty" json:"zapPassiveWaitSeconds,omitempty"`
	// Путь к готовому automation.yaml (относительно каталога scan-as-code или абсолютный).
	ZAPAutomationFile string `yaml:"zapAutomationFile,omitempty" json:"zapAutomationFile,omitempty"`
	// browserId для spiderAjax, напр. firefox-headless, chrome-headless
	ZAPAjaxBrowserID string `yaml:"zapAjaxBrowserId,omitempty" json:"zapAjaxBrowserId,omitempty"`
	// Katana (projectdiscovery/katana): краулинг, вывод -jsonl → находки INFO по URL.
	KatanaDepth         int      `yaml:"katanaDepth,omitempty" json:"katanaDepth,omitempty"`
	KatanaMaxURLs       int      `yaml:"katanaMaxUrls,omitempty" json:"katanaMaxUrls,omitempty"`
	KatanaConcurrency   int      `yaml:"katanaConcurrency,omitempty" json:"katanaConcurrency,omitempty"`
	KatanaTimeoutSecs   int      `yaml:"katanaTimeoutSecs,omitempty" json:"katanaTimeoutSecs,omitempty"`
	KatanaRateLimit     int      `yaml:"katanaRateLimit,omitempty" json:"katanaRateLimit,omitempty"`
	KatanaCrawlDuration string   `yaml:"katanaCrawlDuration,omitempty" json:"katanaCrawlDuration,omitempty"` // например 90s, 2m (флаг -ct)
	KatanaExtraArgs     []string `yaml:"katanaExtraArgs,omitempty" json:"katanaExtraArgs,omitempty"`
	KatanaHeadless      bool     `yaml:"katanaHeadless,omitempty" json:"katanaHeadless,omitempty"`
}

type Budgets struct {
	Discovery    DiscoveryBudget    `yaml:"discovery" json:"discovery"`
	Passive      PassiveBudget      `yaml:"passive" json:"passive"`
	Active       ActiveBudget       `yaml:"active" json:"active"`
	Verification VerificationBudget `yaml:"verification" json:"verification"`
}

type DiscoveryBudget struct {
	MaxDepth          int `yaml:"maxDepth" json:"maxDepth"`
	MaxURLs           int `yaml:"maxUrls" json:"maxUrls"`
	DurationCrawlSecs int `yaml:"durationCrawlSecs" json:"durationCrawlSecs"`
}

type PassiveBudget struct {
	PassiveWaitDelaySecs       int    `yaml:"passiveWaitDelaySecs" json:"passiveWaitDelaySecs"`
	PassiveRuleDefaultSeverity string `yaml:"passiveRuleDefaultSeverity" json:"passiveRuleDefaultSeverity"`
}

type ActiveBudget struct {
	MaxRequestsTotal       int `yaml:"maxRequestsTotal" json:"maxRequestsTotal"`
	MaxRequestsPerEndpoint int `yaml:"maxRequestsPerEndpoint" json:"maxRequestsPerEndpoint"`
	MaxPayloadsPerRule     int `yaml:"maxPayloadsPerRule" json:"maxPayloadsPerRule"`
	Concurrency            int `yaml:"concurrency" json:"concurrency"`
	RateLimitRps           int `yaml:"rateLimitRps" json:"rateLimitRps"`
}

type VerificationBudget struct {
	MaxVerifications  int    `yaml:"maxVerifications" json:"maxVerifications"`
	EvidenceThreshold string `yaml:"evidenceThreshold" json:"evidenceThreshold"`
}

type NoiseControl struct {
	Dedupe        DedupeConfig          `yaml:"dedupe" json:"dedupe"`
	Suppression   SuppressionConfig     `yaml:"suppression" json:"suppression"`
	FalsePositive FalsePositiveWorkflow `yaml:"falsePositiveWorkflow" json:"falsePositiveWorkflow"`
}

type DedupeConfig struct {
	LocationKey        string `yaml:"locationKey" json:"locationKey"`
	ParamNormalization string `yaml:"paramNormalization" json:"paramNormalization"`
}

type SuppressionConfig struct {
	Allowlist []SuppressionRule `yaml:"allowlist" json:"allowlist"`
	Exclude   []SuppressionRule `yaml:"exclude" json:"exclude"`
}

type SuppressionRule struct {
	RuleID      string `yaml:"ruleId,omitempty" json:"ruleId,omitempty"`
	Category    string `yaml:"category,omitempty" json:"category,omitempty"`
	Severity    string `yaml:"severity,omitempty" json:"severity,omitempty"`
	Endpoint    string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	LocationKey string `yaml:"locationKey,omitempty" json:"locationKey,omitempty"`
	Reason      string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

type FalsePositiveWorkflow struct {
	// ProgressiveConfirmation — nil означает «как в DefaultScanAsCode» (true после MergeDefaults).
	ProgressiveConfirmation *bool `yaml:"progressiveConfirmation,omitempty" json:"progressiveConfirmation,omitempty"`
	VerifyOnlyNewOrChanged  *bool `yaml:"verifyOnlyNewOrChanged,omitempty" json:"verifyOnlyNewOrChanged,omitempty"`
}

type Outputs struct {
	Formats []string `yaml:"formats" json:"formats"`
	Docx    *DocxOut `yaml:"docx,omitempty" json:"docx,omitempty"`
	// IncludeEvidence — явное включение/выключение секции Evidence в report.md.
	// Если nil: при отсутствии outputs.docx — показывать доказательства; при наличии docx — как раньше только при docx.includeEvidence: true.
	IncludeEvidence *bool       `yaml:"includeEvidence,omitempty" json:"includeEvidence,omitempty"`
	Paths           OutputPaths `yaml:"paths" json:"paths"`
}

type DocxOut struct {
	TemplateRef     string `yaml:"templateRef,omitempty" json:"templateRef,omitempty"`
	IncludeEvidence bool   `yaml:"includeEvidence" json:"includeEvidence"`
}

type OutputPaths struct {
	ArtifactsDir string `yaml:"artifactsDir" json:"artifactsDir"`
}

type Execution struct {
	Retries        int  `yaml:"retries,omitempty" json:"retries,omitempty"`
	TimeoutJobSecs int  `yaml:"timeoutJobSecs,omitempty" json:"timeoutJobSecs,omitempty"`
	DummyFindings  bool `yaml:"dummyFindings,omitempty" json:"dummyFindings,omitempty"`
}

// DefaultScanAsCode returns minimal valid defaults for missing sections.
func DefaultScanAsCode() ScanAsCode {
	return ScanAsCode{
		Version: "1.0",
		Job:     JobMeta{Name: "default"},
		Scan:    Scan{Preset: "Fast"},
		Budgets: DefaultBudgets(),
		Noise: NoiseControl{
			Dedupe: DedupeConfig{LocationKey: "endpoint+method+paramsNormalized", ParamNormalization: "basic"},
			FalsePositive: FalsePositiveWorkflow{
				ProgressiveConfirmation: boolPtr(true),
				VerifyOnlyNewOrChanged:  boolPtr(false),
			},
		},
		Outputs: Outputs{
			Formats: []string{"json", "md", "docx"},
			Paths:   OutputPaths{ArtifactsDir: "artifacts"},
		},
	}
}

// DefaultBudgets fills zero budgets.
// ReportIncludeEvidence определяет, включать ли секцию Evidence в markdown/DOCX отчёт.
func (c *ScanAsCode) ReportIncludeEvidence() bool {
	o := c.Outputs
	if o.IncludeEvidence != nil {
		return *o.IncludeEvidence
	}
	if o.Docx != nil && o.Docx.IncludeEvidence {
		return true
	}
	if o.Docx != nil && !o.Docx.IncludeEvidence {
		return false
	}
	return true
}

func boolPtr(b bool) *bool { return &b }

// EffectiveProgressiveConfirmation — учитывает nil как true после MergeDefaults.
func (c *ScanAsCode) EffectiveProgressiveConfirmation() bool {
	if c.Noise.FalsePositive.ProgressiveConfirmation != nil {
		return *c.Noise.FalsePositive.ProgressiveConfirmation
	}
	return true
}

// EffectiveVerifyOnlyNewOrChanged — учитывает nil как false после MergeDefaults.
func (c *ScanAsCode) EffectiveVerifyOnlyNewOrChanged() bool {
	if c.Noise.FalsePositive.VerifyOnlyNewOrChanged != nil {
		return *c.Noise.FalsePositive.VerifyOnlyNewOrChanged
	}
	return false
}

func DefaultBudgets() Budgets {
	return Budgets{
		Discovery:    DiscoveryBudget{MaxDepth: 10, MaxURLs: 5000, DurationCrawlSecs: 600},
		Passive:      PassiveBudget{PassiveWaitDelaySecs: 10, PassiveRuleDefaultSeverity: "WARN"},
		Active:       ActiveBudget{MaxRequestsTotal: 100, MaxRequestsPerEndpoint: 10, MaxPayloadsPerRule: 5, Concurrency: 2, RateLimitRps: 5},
		Verification: VerificationBudget{MaxVerifications: 50, EvidenceThreshold: "low"},
	}
}
