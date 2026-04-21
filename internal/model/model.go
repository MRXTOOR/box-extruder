package model

import "time"

// JobStatus mirrors docs/dast API contract.
type JobStatus string

const (
	JobQueued          JobStatus = "QUEUED"
	JobRunning         JobStatus = "RUNNING"
	JobWaitingForAuth  JobStatus = "WAITING_FOR_AUTH"
	JobPartialSuccess  JobStatus = "PARTIAL_SUCCESS"
	JobSucceeded       JobStatus = "SUCCEEDED"
	JobFailed          JobStatus = "FAILED"
	JobCancelled       JobStatus = "CANCELLED"
)

// StepType is a scan plan step.
type StepType string

const (
	StepCrawl           StepType = "crawl"
	StepKatana          StepType = "katana"
	StepPassive         StepType = "passive"
	StepTargetedActive  StepType = "targetedActive"
	StepFullActive      StepType = "fullActive"
	StepVerification    StepType = "verification"
	StepNucleiTemplates StepType = "nucleiTemplates"
	StepNucleiCLI       StepType = "nucleiCLI"
	StepZAPBaseline     StepType = "zapBaseline"
	StepManualReview    StepType = "manualReview"
)

// StepStatus per step.
type StepStatus string

const (
	StepQueued   StepStatus = "QUEUED"
	StepRunning  StepStatus = "RUNNING"
	StepSucceeded StepStatus = "SUCCEEDED"
	StepFailed   StepStatus = "FAILED"
	StepSkipped  StepStatus = "SKIPPED"
)

// AuthVerificationResult for context snapshot.
type AuthVerificationResult string

const (
	AuthAuthenticated     AuthVerificationResult = "Authenticated"
	AuthNotAuthenticated  AuthVerificationResult = "NotAuthenticated"
	AuthUncertain         AuthVerificationResult = "Uncertain"
)

// Finding lifecycle.
type LifecycleStatus string

const (
	LifecycleDetected              LifecycleStatus = "detected"
	LifecycleUnconfirmed           LifecycleStatus = "unconfirmed"
	LifecycleConfirmed             LifecycleStatus = "confirmed"
	LifecycleFalsePositiveSuppressed LifecycleStatus = "false-positive-suppressed"
	LifecycleRecheckRequired       LifecycleStatus = "recheck-required"
)

// EvidenceType for evidence payloads.
type EvidenceType string

const (
	EvidenceHTTPRequestResponse EvidenceType = "httpRequestResponse"
	EvidenceAuthVerification    EvidenceType = "authVerification"
	EvidencePageMarker          EvidenceType = "pageMarker"
	EvidenceTrace               EvidenceType = "trace"
	EvidenceOther               EvidenceType = "other"
	EvidenceManualReview        EvidenceType = "manualReview"
)

// Severity for findings and exit policy.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// StepMetrics optional counters per step.
type StepMetrics struct {
	URLsSeen     int `json:"urlsSeen,omitempty"`
	RequestsMade int `json:"requestsMade,omitempty"`
	FindingsRaw  int `json:"findingsRaw,omitempty"`
}

// JobStep is one planned step execution record.
type JobStep struct {
	StepType StepType    `json:"stepType"`
	Status   StepStatus  `json:"status"`
	Metrics  StepMetrics `json:"metrics,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// Job is the persisted job aggregate (subset for API/storage).
type Job struct {
	JobID            string     `json:"jobId"`
	CreatedAt        time.Time  `json:"createdAt"`
	StartedAt        *time.Time `json:"startedAt,omitempty"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
	Status           JobStatus  `json:"status"`
	ConfigHash       string     `json:"configHash"`
	BudgetsPreset    string     `json:"budgetsPreset,omitempty"`
	Steps            []JobStep  `json:"steps"`
	Error            string     `json:"error,omitempty"`
	ScannedEndpoints []string   `json:"scannedEndpoints,omitempty"`
}

// ContextSnapshot auth + scope without secrets.
type ContextSnapshot struct {
	ContextID           string                 `json:"contextId"`
	TargetBaseURLs      []string               `json:"targetBaseUrls"`
	ScopeAllow          []string               `json:"scopeAllow,omitempty"`
	ScopeDeny           []string               `json:"scopeDeny,omitempty"`
	MaxURLs             int                    `json:"maxUrls,omitempty"`
	AuthProviderChain   []string               `json:"authProviderChain,omitempty"`
	AuthVerification    AuthVerificationResult `json:"authVerification"`
	AuthEvidenceRefs    []string               `json:"authEvidenceRefs,omitempty"`
	CreatedAt           time.Time              `json:"createdAt"`
}

// Finding unified model.
type Finding struct {
	FindingID        string          `json:"findingId"`
	RuleID           string          `json:"ruleId"`
	Category         string          `json:"category"`
	Severity         Severity        `json:"severity"`
	Confidence       float64         `json:"confidence"`
	LocationKey      string          `json:"locationKey"`
	LifecycleStatus  LifecycleStatus `json:"lifecycleStatus"`
	FirstSeenAt      time.Time       `json:"firstSeenAt"`
	LastSeenAt       time.Time       `json:"lastSeenAt"`
	EvidenceRefs     []string        `json:"evidenceRefs"`
	SuppressionReason string         `json:"suppressionReason,omitempty"`
	Title            string          `json:"title,omitempty"`
	Description      string          `json:"description,omitempty"`
	ReviewedBy       string          `json:"reviewedBy,omitempty"`
	ReviewedAt       *time.Time      `json:"reviewedAt,omitempty"`
	ReviewNote       string          `json:"reviewNote,omitempty"`
}

// Evidence artifact.
type Evidence struct {
	EvidenceID string       `json:"evidenceId"`
	Type       EvidenceType `json:"type"`
	StepType   StepType     `json:"stepType"`
	ContextID  string       `json:"contextId"`
	Payload    any          `json:"payload"`
}

// HTTPRequestResponsePayload for DAST evidence.
type HTTPRequestResponsePayload struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"requestHeaders,omitempty"`
	RequestBody     string            `json:"requestBody,omitempty"`
	StatusCode      int               `json:"statusCode"`
	ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	ResponseBodySnippet string        `json:"responseBodySnippet,omitempty"`
}

type ManualReviewPayload struct {
	Action            string `json:"action"` // confirm | reject | reopen
	Note              string `json:"note,omitempty"`
	Actor             string `json:"actor,omitempty"`
	PreviousLifecycle string `json:"previousLifecycle,omitempty"`
}

// AuthVerificationPayload evidence for auth checks.
type AuthVerificationPayload struct {
	ProviderID     string                 `json:"providerId"`
	CheckURL       string                 `json:"checkUrl,omitempty"`
	ExpectedStatus int                    `json:"expectedStatus,omitempty"`
	ActualStatus   int                    `json:"actualStatus,omitempty"`
	Result         AuthVerificationResult `json:"result"`
	Detail         string                 `json:"detail,omitempty"`
}
