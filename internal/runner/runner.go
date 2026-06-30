package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/auth"
	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/payloads"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/google/uuid"
)

// ProgressSink receives human-readable progress (demo UI, tests).
type ProgressSink func(ts time.Time, level, msg string, fields map[string]string)

// ErrCanceled is returned by the pipeline when the job context is canceled
// (e.g. the user requested cancellation via the API/worker).
var ErrCanceled = errors.New("scan canceled")

// Options for a single job execution.
type Options struct {
	// Ctx cancels the run between steps; defaults to context.Background().
	Ctx           context.Context
	WorkDir       string
	ConfigYAML    []byte
	Config        *config.ScanAsCode
	SkipZAPDocker bool
	SkipNucleiCLI bool
	SkipKatanaCLI bool
	// JobID if set reuses workspace (Execute path); empty creates new id in Run.
	JobID string
	// ConfigFileDir is the directory of the scan-as-code file (for resolving relative templatePaths).
	ConfigFileDir string
	// OnProgress optional; called together with AppendOrchestratorLog.
	OnProgress ProgressSink
	// UserID заполняет worker для постановки follow-up задачи в очередь.
	UserID string
	// OnFollowUpEnqueue вызывается после успешного краула (Katana/ZAP), если в конфиге nucleiFollowUp.enabled.
	OnFollowUpEnqueue func(FollowUpEnqueueRequest) error
}

// CreateQueued writes config and job in QUEUED state (REST create flow).
func CreateQueued(opt Options) (string, error) {
	cfg := opt.Config
	if cfg == nil {
		return "", fmt.Errorf("config required")
	}
	jobID := uuid.NewString()
	hash := storage.ConfigHashSHA256(opt.ConfigYAML)
	if err := storage.InitJobDirs(opt.WorkDir, jobID); err != nil {
		return "", err
	}
	if err := storage.WriteConfigSnapshot(opt.WorkDir, jobID, opt.ConfigYAML, hash); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	job := &model.Job{
		JobID:      jobID,
		CreatedAt:  now,
		Status:     model.JobQueued,
		ConfigHash: hash,
	}
	if cfg.Scan.Preset != "" {
		job.BudgetsPreset = cfg.Scan.Preset
	}
	plan := config.EffectivePlan(*cfg)
	for _, s := range plan {
		job.Steps = append(job.Steps, model.JobStep{
			StepType: model.StepType(s.StepType),
			Status:   model.StepQueued,
		})
	}
	if err := storage.WriteJob(opt.WorkDir, job); err != nil {
		return "", err
	}
	_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": now.Format(time.RFC3339), "level": "info", "msg": "job created (queued)"})
	return jobID, nil
}

// Execute is the convenience wrapper around ExecuteWithProgress with no sink.
func Execute(workDir, jobID string, skipZAP bool) error {
	return ExecuteWithProgress(workDir, jobID, skipZAP, nil)
}

// ExecuteWithProgress is like Execute but forwards progress to sink (e.g. CLI demo).
func ExecuteWithProgress(workDir, jobID string, skipZAP bool, on ProgressSink) error {
	cfg, err := storage.LoadScanConfig(workDir, jobID)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(storage.ScanConfigPath(workDir, jobID))
	if err != nil {
		return err
	}
	cfgDir := filepath.Dir(storage.ScanConfigPath(workDir, jobID))
	skipNuclei := os.Getenv("DAST_SKIP_NUCLEI_CLI") == "1"
	skipKatana := os.Getenv("DAST_SKIP_KATANA_CLI") == "1"
	_, err = runPipeline(Options{
		WorkDir:       workDir,
		ConfigYAML:    data,
		Config:        cfg,
		SkipZAPDocker: skipZAP,
		SkipNucleiCLI: skipNuclei,
		SkipKatanaCLI: skipKatana,
		JobID:         jobID,
		ConfigFileDir: cfgDir,
		OnProgress:    on,
	})
	return err
}

func emit(opt Options, jobID, level, msg string) {
	lev := strings.ToUpper(level)
	_ = storage.AppendOrchestratorLog(opt.WorkDir, jobID, "["+lev+"] "+msg)
	if opt.OnProgress != nil {
		opt.OnProgress(time.Now().UTC(), level, msg, nil)
	}
}

// Run executes full pipeline synchronously and returns a new job id.
func Run(opt Options) (string, error) {
	if opt.JobID != "" {
		return runPipeline(opt)
	}
	jobID := uuid.NewString()
	opt.JobID = jobID
	return runPipeline(opt)
}

func runPipeline(opt Options) (string, error) {
	jobID := opt.JobID
	cfg := opt.Config
	if cfg == nil {
		return "", fmt.Errorf("config required")
	}
	if os.Getenv("DAST_SKIP_ZAP") == "1" {
		opt.SkipZAPDocker = true
	}
	ctx := opt.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if applyLoopbackRemapForContainer(cfg) {
		emit(opt, jobID, "info", "Localhost URLs remapped to host.docker.internal for container worker")
	}
	now := time.Now().UTC()
	job, plan, err := initJob(opt, jobID, cfg, now)
	if err != nil {
		return "", err
	}

	authRes, jobRoot, retID, stop, aerr := runAuthPhase(opt, job, jobID, cfg)
	if stop {
		return retID, aerr
	}

	pl := newPipeline(pipeline{
		opt:        opt,
		cfg:        cfg,
		jobID:      jobID,
		jobRoot:    jobRoot,
		job:        job,
		authRes:    authRes,
		httpClient: newScanHTTPClient(cfg, authRes),
	})
	warnPlanOrdering(opt, jobID, plan)

	for i := range job.Steps {
		if ctx.Err() != nil {
			job.Status = model.JobCancelled
			finishJob(opt.WorkDir, job)
			emit(opt, jobID, "warn", "Pipeline canceled before step "+string(job.Steps[i].StepType))
			return jobID, ErrCanceled
		}
		st := &job.Steps[i]
		st.Status = model.StepRunning
		_ = storage.WriteJob(opt.WorkDir, job)
		emit(opt, jobID, "info", fmt.Sprintf("Step %s: start", st.StepType))

		pl.runStep(st, plan[i])

		if st.Status == model.StepRunning {
			st.Status = model.StepSucceeded
		}
		emit(opt, jobID, "info", fmt.Sprintf("Step %s: %s", st.StepType, st.Status))
		_ = storage.WriteJob(opt.WorkDir, job)
	}

	if cfg.Execution != nil && cfg.Execution.DummyFindings {
		df, de := dummyBundle(authRes.Context.ContextID)
		pl.rawFindings = append(pl.rawFindings, df...)
		for _, e := range de {
			pl.evidenceList = append(pl.evidenceList, e)
			pl.evidenceByID[e.EvidenceID] = e
		}
	}

	pl.enqueueNucleiFollowUp()
	if err := pl.finalizeAndReport(now); err != nil {
		return "", err
	}
	return jobID, nil
}

// initJob persists the initial job and config snapshot and returns the job and
// its effective step plan.
func initJob(opt Options, jobID string, cfg *config.ScanAsCode, now time.Time) (*model.Job, []config.ScanStep, error) {
	hash := storage.ConfigHashSHA256(opt.ConfigYAML)
	created := now
	if prev, err := storage.ReadJob(opt.WorkDir, jobID); err == nil && !prev.CreatedAt.IsZero() {
		created = prev.CreatedAt
	}
	if err := storage.InitJobDirs(opt.WorkDir, jobID); err != nil {
		return nil, nil, err
	}
	if err := storage.WriteConfigSnapshot(opt.WorkDir, jobID, opt.ConfigYAML, hash); err != nil {
		return nil, nil, err
	}

	job := &model.Job{
		JobID:      jobID,
		CreatedAt:  created,
		StartedAt:  &now,
		Status:     model.JobRunning,
		ConfigHash: hash,
	}
	if cfg.Scan.Preset != "" {
		job.BudgetsPreset = cfg.Scan.Preset
	}

	plan := config.EffectivePlan(*cfg)
	steps := make([]model.JobStep, 0, len(plan))
	for _, s := range plan {
		steps = append(steps, model.JobStep{
			StepType: model.StepType(s.StepType),
			Status:   model.StepQueued,
		})
	}
	job.Steps = steps
	if err := storage.WriteJob(opt.WorkDir, job); err != nil {
		return nil, nil, err
	}
	_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "info", "msg": "job started"})
	emit(opt, jobID, "info", "Pipeline started")
	return job, plan, nil
}

// runAuthPhase runs authentication, writes context/payloads/evidence and applies
// the auth-failure policy. When stop is true the caller must return (retID, err).
func runAuthPhase(opt Options, job *model.Job, jobID string, cfg *config.ScanAsCode) (res *auth.Result, jobRoot, retID string, stop bool, err error) {
	authEng := auth.NewEngine()
	emit(opt, jobID, "info", "Authentication and context check")
	authRes, err := authEng.Run(cfg)
	if err != nil {
		emit(opt, jobID, "error", "auth error: "+err.Error())
		job.Status = model.JobFailed
		job.Error = err.Error()
		_ = storage.WriteJob(opt.WorkDir, job)
		return nil, "", jobID, true, err
	}
	if err := storage.WriteContext(opt.WorkDir, jobID, &authRes.Context); err != nil {
		return nil, "", "", true, err
	}
	jobRoot = storage.JobRoot(opt.WorkDir, jobID)
	emitPayloadInfo(opt, jobID, jobRoot)
	for _, ev := range authRes.Evidence {
		if err := storage.WriteEvidence(opt.WorkDir, jobID, &ev); err != nil {
			return nil, "", "", true, err
		}
	}
	switch authRes.Context.AuthVerification {
	case model.AuthAuthenticated:
		emit(opt, jobID, "info", "Session: authenticated")
	case model.AuthNotAuthenticated:
		emit(opt, jobID, "warn", "Session: not authenticated")
	case model.AuthUncertain:
		emit(opt, jobID, "warn", "Session: authentication state uncertain")
	}

	if authRes.Context.AuthVerification == model.AuthNotAuthenticated && cfg.Auth != nil && cfg.Auth.Strategy != "none" {
		job.Status = model.JobWaitingForAuth
		_ = storage.WriteJob(opt.WorkDir, job)
		_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "warn", "msg": "auth verification failed"})
		if os.Getenv("DAST_AUTH_FAIL_POLICY") == "fail" {
			emit(opt, jobID, "error", "DAST_AUTH_FAIL_POLICY=fail: stopping")
			job.Status = model.JobFailed
			job.Error = "authentication verification failed"
			finishJob(opt.WorkDir, job)
			return nil, "", jobID, true, fmt.Errorf("auth failed")
		}
		emit(opt, jobID, "warn", "Continuing scan despite auth failure")
	}
	return authRes, jobRoot, "", false, nil
}

// emitPayloadInfo writes payload files and reports which were enabled.
func emitPayloadInfo(opt Options, jobID, jobRoot string) {
	if err := payloads.WritePayloads(jobRoot); err != nil {
		emit(opt, jobID, "warn", "payloads: "+err.Error())
		return
	}
	var parts []string
	if payloads.SQLiEnabled() {
		parts = append(parts, "sqli.txt (?q=)")
	}
	if payloads.XSSEnabled() {
		parts = append(parts, "xss.txt (?x=)")
	}
	if len(parts) > 0 {
		emit(opt, jobID, "info", "Payloads: "+strings.Join(parts, ", ")+" → artifacts/payloads/ (Katana seeds, ZAP requestor, Nuclei)")
	}
}

// newScanHTTPClient builds the HTTP client used by builtin scanners, wiring TLS
// skip and the auth header/cookie injector.
func newScanHTTPClient(cfg *config.ScanAsCode, authRes *auth.Result) *http.Client {
	c := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil && cfg.InsecureSkipTLSVerify {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		c.Transport = tr
	}
	c.Transport = authTransport(c.Transport, authRes.HeaderInject, authRes.CookieHeader)
	return c
}

func finishJob(workDir string, job *model.Job) {
	t := time.Now().UTC()
	job.FinishedAt = &t
	_ = storage.WriteJob(workDir, job)
}

func authTransport(base http.RoundTripper, headers map[string]string, cookie string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &headerRoundTripper{base: base, headers: headers, cookie: cookie}
}

type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
	cookie  string
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if h.cookie != "" {
		existing := req.Header.Get("Cookie")
		if existing != "" {
			req.Header.Set("Cookie", existing+"; "+h.cookie)
		} else {
			req.Header.Set("Cookie", h.cookie)
		}
	}
	return h.base.RoundTrip(req)
}
