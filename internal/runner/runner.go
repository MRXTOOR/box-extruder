package runner

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/auth"
	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/box-extruder/dast/internal/payloads"
	"github.com/box-extruder/dast/internal/report"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/box-extruder/dast/internal/worker/katana"
	"github.com/box-extruder/dast/internal/worker/nuclei"
	zapworker "github.com/box-extruder/dast/internal/worker/zap"
	"github.com/google/uuid"
)

// ProgressSink receives human-readable progress (demo UI, tests).
type ProgressSink func(ts time.Time, level, msg string, fields map[string]string)

// Options for a single job execution.
type Options struct {
	WorkDir       string
	ConfigYAML    []byte
	Config        *config.ScanAsCode
	SkipZAPDocker   bool
	SkipNucleiCLI   bool
	SkipKatanaCLI   bool
	// JobID if set reuses workspace (Execute path); empty creates new id in Run.
	JobID string
	// ConfigFileDir is the directory of the scan-as-code file (for resolving relative templatePaths).
	ConfigFileDir string
	// OnProgress optional; called together with AppendOrchestratorLog.
	OnProgress ProgressSink
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

// Execute loads saved config for jobID and runs pipeline.
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
		WorkDir:        workDir,
		ConfigYAML:     data,
		Config:         cfg,
		SkipZAPDocker:  skipZAP,
		SkipNucleiCLI:  skipNuclei,
		SkipKatanaCLI:  skipKatana,
		JobID:          jobID,
		ConfigFileDir:  cfgDir,
		OnProgress:     on,
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
	hash := storage.ConfigHashSHA256(opt.ConfigYAML)
	created := time.Now().UTC()
	if prev, err := storage.ReadJob(opt.WorkDir, jobID); err == nil && !prev.CreatedAt.IsZero() {
		created = prev.CreatedAt
	}
	if err := storage.InitJobDirs(opt.WorkDir, jobID); err != nil {
		return "", err
	}
	if err := storage.WriteConfigSnapshot(opt.WorkDir, jobID, opt.ConfigYAML, hash); err != nil {
		return "", err
	}

	now := time.Now().UTC()
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
		return "", err
	}
	_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "info", "msg": "job started"})
	emit(opt, jobID, "info", "Pipeline started")

	authEng := auth.NewEngine()
	emit(opt, jobID, "info", "Authentication and context check")
	authRes, err := authEng.Run(cfg)
	if err != nil {
		emit(opt, jobID, "error", "auth error: "+err.Error())
		job.Status = model.JobFailed
		job.Error = err.Error()
		_ = storage.WriteJob(opt.WorkDir, job)
		return jobID, err
	}
	if err := storage.WriteContext(opt.WorkDir, jobID, &authRes.Context); err != nil {
		return "", err
	}
	jobRoot := storage.JobRoot(opt.WorkDir, jobID)
	if err := payloads.WritePayloads(jobRoot); err != nil {
		emit(opt, jobID, "warn", "payloads: "+err.Error())
	} else {
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
	for _, ev := range authRes.Evidence {
		if err := storage.WriteEvidence(opt.WorkDir, jobID, &ev); err != nil {
			return "", err
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
		policy := os.Getenv("DAST_AUTH_FAIL_POLICY")
		if policy == "fail" {
			emit(opt, jobID, "error", "DAST_AUTH_FAIL_POLICY=fail: stopping")
			job.Status = model.JobFailed
			job.Error = "authentication verification failed"
			finishJob(opt.WorkDir, job)
			return jobID, fmt.Errorf("auth failed")
		}
		emit(opt, jobID, "warn", "Continuing scan despite auth failure")
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	httpClient.Transport = authTransport(httpClient.Transport, authRes.HeaderInject, authRes.CookieHeader)

	var rawFindings []model.Finding
	var scannedEndpoints []string
	evidenceList := append([]model.Evidence{}, authRes.Evidence...)
	evidenceByID := map[string]model.Evidence{}
	for i := range evidenceList {
		evidenceByID[evidenceList[i].EvidenceID] = evidenceList[i]
	}
	endpointsSeen := make(map[string]struct{})

	discoveryFeedSeen := make(map[string]struct{})
	var discoveryFeed []string

	var wantDiscoveryFeed, haveDiscovery bool
	nucleiWithFeedIdx := -1
	for i, s := range plan {
		if s.StepType == string(model.StepNucleiTemplates) && s.NucleiIncludeDiscoveredURLs {
			wantDiscoveryFeed = true
			nucleiWithFeedIdx = i
		}
		if s.StepType == string(model.StepKatana) || s.StepType == string(model.StepZAPBaseline) {
			haveDiscovery = true
		}
	}
	if wantDiscoveryFeed && !haveDiscovery {
		emit(opt, jobID, "warn", "Nuclei: nucleiIncludeDiscoveredURLs is set but the plan has no katana or zapBaseline — discovery feed will stay empty")
	}
	if nucleiWithFeedIdx >= 0 {
		for i, s := range plan {
			if i <= nucleiWithFeedIdx {
				continue
			}
			if s.StepType == string(model.StepKatana) || s.StepType == string(model.StepZAPBaseline) {
				emit(opt, jobID, "warn", "Plan order: Nuclei with URL feed runs before katana/zapBaseline — feed is empty when Nuclei runs; reorder steps (crawl/ZAP first)")
				break
			}
		}
	}

	for i := range job.Steps {
		st := &job.Steps[i]
		st.Status = model.StepRunning
		_ = storage.WriteJob(opt.WorkDir, job)
		stepCfg := plan[i]
		emit(opt, jobID, "info", fmt.Sprintf("Step %s: start", st.StepType))

		switch st.StepType {
		case model.StepKatana:
			if opt.SkipKatanaCLI {
				st.Status = model.StepSkipped
				emit(opt, jobID, "info", "Katana CLI: skipped (-skip-katana or DAST_SKIP_KATANA_CLI=1)")
				break
			}
			seeds := katanaSeedURLs(cfg)
			if len(cfg.Targets) > 0 {
				base := cfg.Targets[0].BaseURL
				if payloads.SQLiEnabled() {
					sp := payloads.SQLiPath(jobRoot)
					if _, err := os.Stat(sp); err == nil {
						var err error
						seeds, err = payloads.AppendSQLiSeedURLs(seeds, base, "q", sp)
						if err != nil {
							emit(opt, jobID, "warn", "Katana SQLi seeds: "+err.Error())
						}
					}
				}
				if payloads.XSSEnabled() {
					xp := payloads.XSSPath(jobRoot)
					if _, err := os.Stat(xp); err == nil {
						var err error
						seeds, err = payloads.AppendXSSSeedURLs(seeds, base, "x", xp)
						if err != nil {
							emit(opt, jobID, "warn", "Katana XSS seeds: "+err.Error())
						}
					}
				}
			}
			if len(seeds) == 0 {
				st.Status = model.StepSkipped
				emit(opt, jobID, "info", "Katana: no seed URLs (targets), skipping")
				break
			}
			var hdr []string
			for k, v := range authRes.HeaderInject {
				hdr = append(hdr, fmt.Sprintf("%s: %s", k, v))
			}
			if strings.TrimSpace(os.Getenv("DAST_KATANA_DOCKER_IMAGE")) != "" {
				emit(opt, jobID, "info", "Katana: Docker mode ("+strings.TrimSpace(os.Getenv("DAST_KATANA_DOCKER_IMAGE"))+")")
			} else {
				emit(opt, jobID, "info", "Katana CLI (projectdiscovery/katana, -jsonl)")
			}
			kopts := katanaOptsFromStep(cfg, stepCfg, seeds, hdr)
			kopts.ContextID = authRes.Context.ContextID
			kf, ke, kerr := katana.RunCLI(kopts)
			if kerr != nil {
				st.Status = model.StepFailed
				st.Error = kerr.Error()
				emit(opt, jobID, "error", "Katana CLI: "+st.Error)
				_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "error", "msg": st.Error, "step": string(st.StepType)})
			} else {
				emit(opt, jobID, "info", fmt.Sprintf("Katana: URLs in output: %d", len(kf)))
				rawFindings = append(rawFindings, kf...)
				for _, e := range ke {
					evidenceList = append(evidenceList, e)
					evidenceByID[e.EvidenceID] = e
				}
				// Collect scanned endpoints from evidence URLs (normalized: no query params)
				for _, e := range ke {
					if ep := extractEndpoint(e); ep != "" {
						if _, seen := endpointsSeen[ep]; !seen {
							endpointsSeen[ep] = struct{}{}
							scannedEndpoints = append(scannedEndpoints, ep)
						}
					}
				}
				feedAppend(discoveryFeedSeen, &discoveryFeed, harvestHTTPURLsFromFindings(kf, evidenceByID))
				st.Metrics.FindingsRaw = len(kf)
				st.Metrics.URLsSeen = len(kf)
				st.Status = model.StepSucceeded
			}
		case model.StepCrawl, model.StepPassive, model.StepTargetedActive, model.StepFullActive, model.StepVerification:
			st.Metrics.URLsSeen = 1
			// Placeholder: real crawl/active would run here
		case model.StepZAPBaseline:
			if opt.SkipZAPDocker {
				st.Status = model.StepSkipped
				emit(opt, jobID, "info", "Step zapBaseline: skipped (-skip-zap)")
				break
			}
			base := cfg.Targets[0].BaseURL
			zapDir := filepath.Join(storage.JobRoot(opt.WorkDir, jobID), "zap-out")
			authHeaders := map[string]string{}
			for k, v := range authRes.HeaderInject {
				authHeaders[k] = v
			}
			var zf []model.Finding
			var ze []model.Evidence
			var zerr error
			sqlPayloadPath := ""
			if payloads.SQLiEnabled() {
				p := payloads.SQLiPath(jobRoot)
				if _, err := os.Stat(p); err == nil {
					sqlPayloadPath = p
				}
			}
			xssPayloadPath := ""
			if payloads.XSSEnabled() {
				p := payloads.XSSPath(jobRoot)
				if _, err := os.Stat(p); err == nil {
					xssPayloadPath = p
				}
			}
			if zapworker.UseAutomation(stepCfg) {
				emit(opt, jobID, "info", "ZAP: Automation Framework (spider / Ajax spider if enabled)")
				zf, ze, zerr = zapworker.RunAutomation(base, zapDir, stepCfg.ZAPDockerImage, opt.ConfigFileDir, cfg.Scope.Allow, stepCfg, authHeaders, sqlPayloadPath, xssPayloadPath)
			} else {
				emit(opt, jobID, "info", "ZAP: baseline script (docker)")
				zf, ze, zerr = zapworker.RunBaseline(base, zapDir, stepCfg.ZAPDockerImage, authHeaders)
			}
			if zerr != nil {
				st.Status = model.StepFailed
				st.Error = zerr.Error()
				emit(opt, jobID, "error", "ZAP: "+st.Error)
				_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "error", "msg": st.Error, "step": string(st.StepType)})
			} else {
				emit(opt, jobID, "info", fmt.Sprintf("ZAP: findings %d", len(zf)))
				rawFindings = append(rawFindings, zf...)
				for _, e := range ze {
					e.ContextID = authRes.Context.ContextID
					evidenceList = append(evidenceList, e)
					evidenceByID[e.EvidenceID] = e
				}
				// Collect scanned endpoints from ZAP evidence URLs (normalized)
				for _, e := range ze {
					if ep := extractEndpoint(e); ep != "" {
						if _, seen := endpointsSeen[ep]; !seen {
							endpointsSeen[ep] = struct{}{}
							scannedEndpoints = append(scannedEndpoints, ep)
						}
					}
				}
				feedAppend(discoveryFeedSeen, &discoveryFeed, harvestHTTPURLsFromFindings(zf, evidenceByID))
				st.Metrics.FindingsRaw = len(zf)
				st.Status = model.StepSucceeded
			}
		case model.StepNucleiTemplates:
			paths := resolveTemplatePaths(opt.ConfigFileDir, stepCfg.TemplatePaths, opt.WorkDir)
			paths = appendSQLiBuiltinTemplatePath(paths, opt.ConfigFileDir)
			paths = appendXSSBuiltinTemplatePath(paths, opt.ConfigFileDir)
			if nucleiUseOfficialCLI(stepCfg) {
				if opt.SkipNucleiCLI {
					st.Status = model.StepSkipped
					emit(opt, jobID, "info", "Nuclei CLI: skipped (-skip-nuclei or DAST_SKIP_NUCLEI_CLI=1)")
					break
				}
				exist := existingPaths(paths)
				if payloads.SQLiEnabled() {
					sqliAbs := payloads.SQLiPath(jobRoot)
					if _, err := os.Stat(sqliAbs); err == nil {
						gen := filepath.Join(jobRoot, "artifacts", "payloads", "sqli-nuclei-cli.yaml")
						if err := payloads.WriteNucleiCLITemplate(sqliAbs, gen); err == nil {
							exist = append(exist, gen)
						}
					}
				}
				if payloads.XSSEnabled() {
					xssAbs := payloads.XSSPath(jobRoot)
					if _, err := os.Stat(xssAbs); err == nil {
						gen := filepath.Join(jobRoot, "artifacts", "payloads", "xss-nuclei-cli.yaml")
						if err := payloads.WriteNucleiXSSCLITemplate(xssAbs, gen); err == nil {
							exist = append(exist, gen)
						}
					}
				}
				if len(exist) == 0 {
					st.Status = model.StepSkipped
					emit(opt, jobID, "info", "Nuclei CLI: no existing template paths, skipping")
					break
				}
				var bases []string
				for _, t := range cfg.Targets {
					if u := strings.TrimSpace(t.BaseURL); u != "" {
						bases = append(bases, u)
					}
				}
				if stepCfg.NucleiIncludeDiscoveredURLs {
					if len(discoveryFeed) == 0 {
						emit(opt, jobID, "warn", "Nuclei: nucleiIncludeDiscoveredURLs is set but URL feed is empty (put Katana/ZAP before Nuclei in the plan)")
					} else {
						emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: added feed URLs to targets (feed size %d, scope/budget limits apply)", len(discoveryFeed)))
					}
				}
				targetLines := nucleiCLITargetLines(cfg, bases, discoveryFeed, stepCfg.NucleiIncludeDiscoveredURLs)
				listPath, werr := writeNucleiTargetsFile(opt.WorkDir, jobID, targetLines)
				if werr != nil {
					st.Status = model.StepFailed
					st.Error = werr.Error()
					emit(opt, jobID, "error", "Nuclei CLI: "+st.Error)
					break
				}
				emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: %d targets (file %s)", len(targetLines), filepath.Base(listPath)))
				var hdr []string
				for k, v := range authRes.HeaderInject {
					hdr = append(hdr, fmt.Sprintf("%s: %s", k, v))
				}
				emit(opt, jobID, "info", "Nuclei CLI (projectdiscovery/nuclei, -jsonl, -l targets)")
				nf, ne, nerr := nuclei.RunCLI(nuclei.CLIOptions{
					ListFile:      listPath,
					TemplatePaths: exist,
					Headers:       hdr,
					ExtraArgs:     stepCfg.NucleiExtraArgs,
					RateLimit:     stepCfg.NucleiRateLimit,
					ContextID:     authRes.Context.ContextID,
					Dedupe:        cfg.Noise.Dedupe,
				})
				if nerr != nil {
					st.Status = model.StepFailed
					st.Error = nerr.Error()
					emit(opt, jobID, "error", "Nuclei CLI: "+st.Error)
					_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "error", "msg": st.Error, "step": string(st.StepType)})
				} else {
					emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: matches %d", len(nf)))
					rawFindings = append(rawFindings, nf...)
					for _, e := range ne {
						evidenceList = append(evidenceList, e)
						evidenceByID[e.EvidenceID] = e
					}
					st.Metrics.FindingsRaw = len(nf)
					st.Status = model.StepSucceeded
				}
				break
			}
			tpls, terr := nuclei.LoadTemplates(paths)
			if terr != nil || len(tpls) == 0 {
				st.Status = model.StepSkipped
				if terr != nil {
					st.Error = terr.Error()
					emit(opt, jobID, "warn", "Nuclei templates: skipped — "+st.Error)
				} else {
					emit(opt, jobID, "info", "Nuclei templates: no files, skipping")
				}
			} else {
				var bases []string
				for _, t := range cfg.Targets {
					if u := strings.TrimSpace(t.BaseURL); u != "" {
						bases = append(bases, u)
					}
				}
				if stepCfg.NucleiIncludeDiscoveredURLs {
					if len(discoveryFeed) == 0 {
						emit(opt, jobID, "warn", "Nuclei: nucleiIncludeDiscoveredURLs is set but URL feed is empty (builtin engine only adds new origins)")
					} else {
						emit(opt, jobID, "info", fmt.Sprintf("Nuclei (builtin): added origins from feed to bases (feed paths %d)", len(discoveryFeed)))
					}
				}
				bases = nucleiBuiltinBases(cfg, bases, discoveryFeed, stepCfg.NucleiIncludeDiscoveredURLs)
				nf, ne, _ := nuclei.Run(httpClient, bases, tpls, authRes.Context.ContextID, cfg.Noise.Dedupe, jobRoot)
				emit(opt, jobID, "info", fmt.Sprintf("Nuclei templates: matches %d", len(nf)))
				rawFindings = append(rawFindings, nf...)
				for _, e := range ne {
					evidenceList = append(evidenceList, e)
					evidenceByID[e.EvidenceID] = e
				}
				st.Metrics.FindingsRaw = len(nf)
				st.Status = model.StepSucceeded
			}
		default:
			st.Status = model.StepSucceeded
		}

		if st.Status == model.StepRunning {
			st.Status = model.StepSucceeded
		}
		emit(opt, jobID, "info", fmt.Sprintf("Step %s: %s", st.StepType, st.Status))
		_ = storage.WriteJob(opt.WorkDir, job)
	}

	if cfg.Execution != nil && cfg.Execution.DummyFindings {
		df, de := dummyBundle(authRes.Context.ContextID)
		rawFindings = append(rawFindings, df...)
		for _, e := range de {
			evidenceList = append(evidenceList, e)
			evidenceByID[e.EvidenceID] = e
		}
	}

	for i := range rawFindings {
		for _, eid := range rawFindings[i].EvidenceRefs {
			if ev, ok := evidenceByID[eid]; ok {
				ev.ContextID = authRes.Context.ContextID
				evidenceByID[eid] = ev
			}
		}
	}

	for _, ev := range evidenceByID {
		_ = storage.WriteEvidence(opt.WorkDir, jobID, &ev)
	}

	if err := storage.WriteFindingsJSON(opt.WorkDir, jobID, "findings-raw.json", rawFindings); err != nil {
		return "", err
	}
	emit(opt, jobID, "info", fmt.Sprintf("Raw findings written: %d", len(rawFindings)))

	final := noise.Apply(*cfg, rawFindings, evidenceByID)
	if err := storage.WriteFindingsJSON(opt.WorkDir, jobID, "findings-final.json", final); err != nil {
		return "", err
	}
	emit(opt, jobID, "info", fmt.Sprintf("After noise control: %d findings", len(final)))

	baseURL := ""
	if len(cfg.Targets) > 0 {
		baseURL = cfg.Targets[0].BaseURL
	}
	preset := cfg.Scan.Preset
	if preset == "" {
		preset = "custom"
	}
	md := report.RenderMarkdown(cfg.Job.Name, baseURL, preset, now, time.Now().UTC(), final, evidenceByID, cfg.ReportIncludeEvidence(), cfg.Budgets.Verification.EvidenceThreshold, nil, scannedEndpoints)
	if err := storage.WriteReportMD(opt.WorkDir, jobID, md); err != nil {
		return "", err
	}
	mdPath := filepath.Join(storage.JobRoot(opt.WorkDir, jobID), "reports", "report.md")
	docxPath := filepath.Join(storage.JobRoot(opt.WorkDir, jobID), "reports", "report.docx")
	htmlPath := filepath.Join(storage.JobRoot(opt.WorkDir, jobID), "reports", "report.html")
	ref := ""
	if cfg.Outputs.Docx != nil {
		ref = report.ResolveReferenceDoc(cfg.Outputs.Docx.TemplateRef, opt.WorkDir)
	}
	_ = report.PandocToDocxOptional(mdPath, docxPath, ref)
	_ = report.WriteHTMLReport(cfg.Job.Name, baseURL, now, time.Now().UTC(), final, scannedEndpoints, htmlPath)
	_ = storage.WriteEndpointsTxt(opt.WorkDir, jobID, scannedEndpoints)
	emit(opt, jobID, "info", "Markdown saved; DOCX if pandoc in PATH, else reports/report.html for Word/LibreOffice")

	partial := false
	for _, st := range job.Steps {
		if st.Status == model.StepFailed {
			partial = true
		}
	}
	if partial {
		job.Status = model.JobPartialSuccess
	} else {
		job.Status = model.JobSucceeded
	}
	// Save scanned endpoints to job
	if len(scannedEndpoints) > 0 {
		job.ScannedEndpoints = scannedEndpoints
	}
	finishJob(opt.WorkDir, job)
	emit(opt, jobID, "info", "Done, job status: "+string(job.Status))
	_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "info", "msg": "job finished", "status": string(job.Status)})
	return jobID, nil
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

func dummyBundle(ctxID string) ([]model.Finding, []model.Evidence) {
	now := time.Now().UTC()
	evConfirmed := uuid.NewString()
	evUnconf := uuid.NewString()
	evSupp := uuid.NewString()
	loc := "GET https://example.invalid/search?q=test"
	findings := []model.Finding{
		{
			FindingID:       uuid.NewString(),
			RuleID:          "demo-xss-001",
			Category:        "XSS",
			Severity:        model.SeverityHigh,
			Confidence:      0.9,
			LocationKey:     loc,
			LifecycleStatus: model.LifecycleConfirmed,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			EvidenceRefs:    []string{evConfirmed},
			Title:           "Demo reflected XSS (confirmed)",
		},
		{
			FindingID:       uuid.NewString(),
			RuleID:          "demo-sqli-weak",
			Category:        "SQL Injection",
			Severity:        model.SeverityMedium,
			Confidence:      0.4,
			LocationKey:     loc + "&id=1",
			LifecycleStatus: model.LifecycleUnconfirmed,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			EvidenceRefs:    []string{evUnconf},
			Title:           "Demo SQLi indicator (unconfirmed)",
		},
		{
			FindingID:         uuid.NewString(),
			RuleID:            "demo-info",
			Category:          "Informational",
			Severity:          model.SeverityInfo,
			Confidence:        0.99,
			LocationKey:       "GET https://example.invalid/robots.txt",
			LifecycleStatus:   model.LifecycleFalsePositiveSuppressed,
			FirstSeenAt:       now,
			LastSeenAt:        now,
			EvidenceRefs:      []string{evSupp},
			Title:             "Demo suppressed finding",
			SuppressionReason: "baseline noise",
		},
	}
	evidence := []model.Evidence{
		{
			EvidenceID: evConfirmed,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepPassive,
			ContextID:  ctxID,
			Payload: model.HTTPRequestResponsePayload{
				Method:              "GET",
				URL:                 "https://example.invalid/search?q=%3Cscript%3E",
				StatusCode:          200,
				ResponseBodySnippet: "<html><script>alert(1)</script></html>",
			},
		},
		{
			EvidenceID: evUnconf,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepPassive,
			ContextID:  ctxID,
			Payload: model.HTTPRequestResponsePayload{
				Method:              "GET",
				URL:                 "https://example.invalid/search?q=1",
				StatusCode:          500,
				ResponseBodySnippet: "syntax error near",
			},
		},
		{
			EvidenceID: evSupp,
			Type:       model.EvidenceHTTPRequestResponse,
			StepType:   model.StepPassive,
			ContextID:  ctxID,
			Payload: model.HTTPRequestResponsePayload{
				Method:     "GET",
				URL:      "https://example.invalid/robots.txt",
				StatusCode: 200,
			},
		},
	}
	return findings, evidence
}

func appendSQLiBuiltinTemplatePath(paths []string, configFileDir string) []string {
	if !payloads.SQLiEnabled() || strings.TrimSpace(configFileDir) == "" {
		return paths
	}
	t := filepath.Join(configFileDir, "templates", "sqli-query-probe.yaml")
	if _, err := os.Stat(t); err == nil {
		paths = append(paths, t)
	}
	return paths
}

func appendXSSBuiltinTemplatePath(paths []string, configFileDir string) []string {
	if !payloads.XSSEnabled() || strings.TrimSpace(configFileDir) == "" {
		return paths
	}
	t := filepath.Join(configFileDir, "templates", "xss-query-probe.yaml")
	if _, err := os.Stat(t); err == nil {
		paths = append(paths, t)
	}
	return paths
}

func katanaSeedURLs(cfg *config.ScanAsCode) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, t := range cfg.Targets {
		u := strings.TrimSpace(t.BaseURL)
		if u != "" {
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				out = append(out, u)
			}
		}
		for _, sp := range t.StartPoints {
			sp = strings.TrimSpace(sp)
			if sp == "" {
				continue
			}
			if _, ok := seen[sp]; !ok {
				seen[sp] = struct{}{}
				out = append(out, sp)
			}
		}
	}
	return out
}

func katanaOptsFromStep(cfg *config.ScanAsCode, step config.ScanStep, seeds, headers []string) katana.CLIOptions {
	o := katana.CLIOptions{
		Targets:   seeds,
		Headers:   headers,
		Headless:  step.KatanaHeadless,
		ExtraArgs: step.KatanaExtraArgs,
		Dedupe:    cfg.Noise.Dedupe,
	}
	if step.KatanaDepth > 0 {
		o.Depth = step.KatanaDepth
	} else if cfg.Budgets.Discovery.MaxDepth > 0 {
		o.Depth = cfg.Budgets.Discovery.MaxDepth
	}
	if step.KatanaConcurrency > 0 {
		o.Concurrency = step.KatanaConcurrency
	} else if cfg.Budgets.Active.Concurrency > 0 {
		o.Concurrency = cfg.Budgets.Active.Concurrency
	}
	if step.KatanaTimeoutSecs > 0 {
		o.TimeoutSecs = step.KatanaTimeoutSecs
	}
	if step.KatanaRateLimit > 0 {
		o.RateLimit = step.KatanaRateLimit
	} else if cfg.Budgets.Active.RateLimitRps > 0 {
		o.RateLimit = cfg.Budgets.Active.RateLimitRps
	}
	if d := strings.TrimSpace(step.KatanaCrawlDuration); d != "" {
		o.CrawlDuration = d
	} else if cfg.Budgets.Discovery.DurationCrawlSecs > 0 {
		o.CrawlDuration = fmt.Sprintf("%ds", cfg.Budgets.Discovery.DurationCrawlSecs)
	}
	for _, re := range cfg.Scope.Allow {
		re = strings.TrimSpace(re)
		if re != "" {
			o.CrawlScope = append(o.CrawlScope, re)
		}
	}
	for _, re := range cfg.Scope.Deny {
		re = strings.TrimSpace(re)
		if re != "" {
			o.CrawlOutScope = append(o.CrawlOutScope, re)
		}
	}
	return o
}

func nucleiUseOfficialCLI(step config.ScanStep) bool {
	return strings.EqualFold(strings.TrimSpace(step.NucleiEngine), "cli")
}

func existingPaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// resolveTemplatePaths ищет относительные пути: рядом с YAML, затем у родителя workDir (корень репо при work=./work),
// затем в workDir. Нужно для задач из API: config лежит в work/jobs/<id>/config/, а templates/ — в корне проекта.
func resolveTemplatePaths(configDir string, paths []string, workDir string) []string {
	repoRoot := filepath.Clean(filepath.Join(workDir, ".."))
	if len(paths) == 0 {
		for _, d := range []string{filepath.Join(repoRoot, "templates"), filepath.Join(workDir, "templates")} {
			if pathExists(d) {
				return []string{d}
			}
		}
		return []string{filepath.Join(workDir, "templates")}
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			out = append(out, p)
			continue
		}
		if resolved := resolveOneRelativeTemplatePath(configDir, p, workDir, repoRoot); resolved != "" {
			out = append(out, resolved)
			continue
		}
		if configDir != "" {
			out = append(out, filepath.Join(configDir, p))
			continue
		}
		out = append(out, p)
	}
	return out
}

func resolveOneRelativeTemplatePath(configDir, p, workDir, repoRoot string) string {
	candidates := []string{}
	if configDir != "" {
		candidates = append(candidates, filepath.Join(configDir, p))
	}
	candidates = append(candidates, filepath.Join(repoRoot, p), filepath.Join(workDir, p), p)
	for _, c := range candidates {
		if pathExists(c) {
			return c
		}
	}
	return ""
}

// extractEndpoint извлекает URL из evidence (полный URL с query params).
// Фильтрует URL с payload для XSS/SQLi атак — сохраняет только реальные эндпоинты.
func extractEndpoint(e model.Evidence) string {
	rawURL := ""
	switch p := e.Payload.(type) {
	case model.HTTPRequestResponsePayload:
		rawURL = p.URL
	case map[string]any:
		if v, ok := p["url"].(string); ok {
			rawURL = v
		}
	}
	if rawURL == "" {
		return ""
	}
	// Валидация URL
	_, err := parseURL(rawURL)
	if err != nil {
		return ""
	}
	// Фильтруем URL с payload для XSS/SQLi атак
	if isAttackPayloadURL(rawURL) {
		return ""
	}
	return rawURL
}

// isAttackPayloadURL проверяет, содержит ли URL известные payload-паттерны XSS/SQLi
func isAttackPayloadURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return false
	}
	// Проверяем raw и decoded query
	rawQ := strings.ToLower(u.RawQuery)
	decodedQ := ""
	if d, err := url.QueryUnescape(u.RawQuery); err == nil {
		decodedQ = strings.ToLower(d)
	}
	// Специфичные XSS payload-паттерны
	xssPatterns := []string{
		"alert(", "prompt(", "confirm(",
		"document.cookie", "document.location", "document.write",
		"string.fromcharcode", "eval(",
		"<script", "%3cscript", "%3c%73cript",
		"onerror=alert", "onerror=prompt", "onerror=confirm",
		"onload=alert", "onload=prompt",
		"javascript:alert", "javascript:prompt",
		"data:text/html", "vbscript:",
		"<svg/onload", "%3csvg/onload",
		"<img/src", "%3cimg/src",
		"<iframe", "%3ciframe",
		"expression(alert",
	}
	// Специфичные SQLi payload-паттерны
	sqliPatterns := []string{
		"' or 1=1", "' and 1=1", "' union select", "' union all select",
		"' insert into", "' drop table", "' truncate ",
		" or 1=1", " and 1=1", " or '1'='1", " and '1'='1",
		"sleep(", "benchmark(", "waitfor delay", "waitfor time",
		"xp_cmdshell", "xp_dirtree", "xp_fileexist",
		"load_file(", "into outfile", "into dumpfile",
		"information_schema", "sysobjects", "syscolumns",
		"@@version", "@@servername",
		"convert(int", "cast(",
	}
	// Проверяем оба варианта
	for _, q := range []string{rawQ, decodedQ} {
		if q == "" {
			continue
		}
		for _, pat := range xssPatterns {
			if strings.Contains(q, pat) {
				return true
			}
		}
		for _, pat := range sqliPatterns {
			if strings.Contains(q, pat) {
				return true
			}
		}
	}
	return false
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// Пробуем добавить схему если отсутствует
		if strings.HasPrefix(raw, "//") {
			return url.Parse("https:" + raw)
		}
		if strings.HasPrefix(raw, "/") {
			return url.Parse("http://localhost" + raw)
		}
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return nil, fmt.Errorf("empty host in URL: %s", raw)
	}
	return u, nil
}
