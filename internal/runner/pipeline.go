package runner

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/auth"
	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/payloads"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/box-extruder/dast/internal/worker/httpx"
	"github.com/box-extruder/dast/internal/worker/katana"
	"github.com/box-extruder/dast/internal/worker/nuclei"
	"github.com/box-extruder/dast/internal/worker/wapiti"
	zapworker "github.com/box-extruder/dast/internal/worker/zap"
)

// pipeline carries the mutable state shared by all scan steps so each scanner
// can live in its own method instead of one giant switch in runPipeline.
type pipeline struct {
	opt        Options
	cfg        *config.ScanAsCode
	jobID      string
	jobRoot    string
	job        *model.Job
	authRes    *auth.Result
	httpClient *http.Client

	rawFindings      []model.Finding
	scannedEndpoints []string
	evidenceList     []model.Evidence
	evidenceByID     map[string]model.Evidence
	endpointsSeen    map[string]struct{}

	discoveryFeed     []string
	discoveryFeedSeen map[string]struct{}
}

// newPipeline takes a base pipeline carrying the run dependencies (opt, cfg,
// jobID, jobRoot, job, authRes, httpClient) and initializes the derived
// accumulators (evidence index, dedupe sets).
func newPipeline(base pipeline) *pipeline {
	base.evidenceList = append([]model.Evidence{}, base.authRes.Evidence...)
	base.evidenceByID = make(map[string]model.Evidence, len(base.evidenceList))
	for i := range base.evidenceList {
		base.evidenceByID[base.evidenceList[i].EvidenceID] = base.evidenceList[i]
	}
	base.endpointsSeen = make(map[string]struct{})
	base.discoveryFeedSeen = make(map[string]struct{})
	return &base
}

// collectOpts controls how a scanner's output is folded into the shared state.
type collectOpts struct {
	setContextID     bool
	collectEndpoints bool
	addToFeed        bool
}

// collect appends findings and evidence, optionally harvesting scanned
// endpoints and the discovery feed. It centralizes the pattern that was
// duplicated across the Katana/ZAP/Wapiti/Nuclei steps.
func (pl *pipeline) collect(findings []model.Finding, evs []model.Evidence, o collectOpts) {
	pl.rawFindings = append(pl.rawFindings, findings...)
	for _, e := range evs {
		if o.setContextID {
			e.ContextID = pl.authRes.Context.ContextID
		}
		pl.evidenceList = append(pl.evidenceList, e)
		pl.evidenceByID[e.EvidenceID] = e
	}
	if o.collectEndpoints {
		for _, e := range evs {
			ep := extractEndpoint(e)
			if ep == "" {
				continue
			}
			if _, seen := pl.endpointsSeen[ep]; !seen {
				pl.endpointsSeen[ep] = struct{}{}
				pl.scannedEndpoints = append(pl.scannedEndpoints, ep)
			}
		}
	}
	if o.addToFeed {
		feedAppend(pl.discoveryFeedSeen, &pl.discoveryFeed, harvestHTTPURLsFromFindings(findings, pl.evidenceByID, discoveryPreserveQuery(pl.cfg)))
	}
}

// runStep dispatches a single plan step to its scanner implementation.
func (pl *pipeline) runStep(st *model.JobStep, stepCfg config.ScanStep) {
	switch st.StepType {
	case model.StepKatana:
		pl.runKatana(st, stepCfg)
	case model.StepHttpx:
		pl.runHttpx(st, stepCfg)
	case model.StepCrawl, model.StepPassive, model.StepTargetedActive, model.StepFullActive, model.StepVerification:
		st.Metrics.URLsSeen = 1 // Placeholder: real crawl/active would run here.
	case model.StepZAPBaseline:
		pl.runZAP(st, stepCfg)
	case model.StepWapiti:
		pl.runWapiti(st, stepCfg)
	case model.StepNucleiTemplates:
		pl.runNuclei(st, stepCfg)
	default:
		st.Status = model.StepSucceeded
	}
}

func (pl *pipeline) runKatana(st *model.JobStep, stepCfg config.ScanStep) {
	opt, cfg, jobID, jobRoot, authRes := pl.opt, pl.cfg, pl.jobID, pl.jobRoot, pl.authRes
	if opt.SkipKatanaCLI {
		st.Status = model.StepSkipped
		emit(opt, jobID, "info", "Katana CLI: skipped (-skip-katana or DAST_SKIP_KATANA_CLI=1)")
		return
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
		return
	}
	var hdr []string
	for k, v := range authRes.HeaderInject {
		hdr = append(hdr, fmt.Sprintf("%s: %s", k, v))
	}
	if len(hdr) == 0 && cfg.Auth != nil {
		emit(opt, jobID, "warn", "Katana: нет Authorization/Cookie для цели — обход только того, что отдаёт сайт без сессии (часто мало URL)")
	} else if len(hdr) > 0 {
		keys := make([]string, 0, len(authRes.HeaderInject))
		for k := range authRes.HeaderInject {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		emit(opt, jobID, "info", "Katana: для запросов передаются заголовки: "+strings.Join(keys, ", "))
	}
	if strings.TrimSpace(os.Getenv("DAST_KATANA_DOCKER_IMAGE")) != "" {
		emit(opt, jobID, "info", "Katana: Docker mode ("+strings.TrimSpace(os.Getenv("DAST_KATANA_DOCKER_IMAGE"))+")")
	} else {
		emit(opt, jobID, "info", "Katana CLI (projectdiscovery/katana, -jsonl)")
	}
	kopts := katanaOptsFromStep(cfg, stepCfg, seeds, hdr)
	kopts.ContextID = authRes.Context.ContextID
	if kopts.Headless {
		// First headless run may download Chromium (rod); allow extra wall-clock time.
		kopts.Timeout = 20 * time.Minute
	}
	kf, ke, kerr := katana.RunCLI(kopts)
	if kerr != nil && kopts.Headless && katana.HeadlessSetupLikely(kerr) {
		emit(opt, jobID, "warn", "Katana headless failed — retrying without -headless (keep -jc for JS endpoints)")
		retry := kopts
		retry.Headless = false
		retry.Timeout = 0
		kf, ke, kerr = katana.RunCLI(retry)
	}
	if kerr != nil {
		st.Status = model.StepFailed
		st.Error = kerr.Error()
		emit(opt, jobID, "error", "Katana CLI: "+st.Error)
		_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "error", "msg": st.Error, "step": string(st.StepType)})
		return
	}
	emit(opt, jobID, "info", fmt.Sprintf("Katana: URLs in output: %d", len(kf)))
	pl.collect(kf, ke, collectOpts{collectEndpoints: true, addToFeed: true})
	st.Metrics.FindingsRaw = len(kf)
	st.Metrics.URLsSeen = len(kf)
	st.Status = model.StepSucceeded
}

func (pl *pipeline) runHttpx(st *model.JobStep, stepCfg config.ScanStep) {
	opt, cfg, jobID, authRes := pl.opt, pl.cfg, pl.jobID, pl.authRes
	if !stepCfg.Enabled {
		st.Status = model.StepSkipped
		return
	}
	targets := httpx.FilterFeedURLs(pl.discoveryFeed)
	if len(targets) == 0 {
		st.Status = model.StepSkipped
		emit(opt, jobID, "info", "httpx: no URLs in discovery feed, skipping")
		return
	}
	var hdr []string
	for k, v := range authRes.HeaderInject {
		hdr = append(hdr, fmt.Sprintf("%s: %s", k, v))
	}
	outDir := filepath.Join(storage.JobRoot(opt.WorkDir, jobID), "httpx-out")
	emit(opt, jobID, "info", fmt.Sprintf("httpx: probing %d URLs", len(targets)))
	hf, he, alive, dead, herr := httpx.RunCLI(httpx.CLIOptions{
		Targets:   targets,
		Headers:   hdr,
		OutDir:    outDir,
		ContextID: authRes.Context.ContextID,
		Dedupe:    cfg.Noise.Dedupe,
	})
	if herr != nil {
		st.Status = model.StepFailed
		st.Error = herr.Error()
		emit(opt, jobID, "error", "httpx: "+st.Error)
		_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "error", "msg": st.Error, "step": string(st.StepType)})
		return
	}
	pl.collect(hf, he, collectOpts{collectEndpoints: true, addToFeed: false})
	if httpx.Drop4xxEnabled() && len(dead) > 0 {
		deadSet := make(map[string]struct{}, len(dead))
		for _, u := range dead {
			deadSet[u] = struct{}{}
		}
		filtered := pl.discoveryFeed[:0]
		for _, u := range pl.discoveryFeed {
			if _, drop := deadSet[u]; drop {
				continue
			}
			filtered = append(filtered, u)
		}
		pl.discoveryFeed = filtered
		emit(opt, jobID, "info", fmt.Sprintf("httpx: removed %d dead URLs from feed", len(dead)))
	}
	st.Metrics.FindingsRaw = len(hf)
	st.Metrics.URLsSeen = len(alive)
	st.Status = model.StepSucceeded
	emit(opt, jobID, "info", fmt.Sprintf("httpx: %d live URLs", len(alive)))
}

func (pl *pipeline) runZAP(st *model.JobStep, stepCfg config.ScanStep) {
	opt, cfg, jobID, jobRoot, authRes := pl.opt, pl.cfg, pl.jobID, pl.jobRoot, pl.authRes
	if opt.SkipZAPDocker {
		st.Status = model.StepSkipped
		emit(opt, jobID, "info", "Step zapBaseline: skipped (DAST_SKIP_ZAP=1 or -skip-zap)")
		return
	}
	// ZAP spiders only from the configured target base URLs and startPoints.
	// The Katana discoveryFeed is NOT merged here: merging thousands of
	// Katana-discovered URLs (including attack payloads from SQLi/XSS seeds) as
	// ZAP spider seeds causes OOM kills and makes ZAP spider API JSON endpoints
	// instead of navigating the SPA. Katana results go to Nuclei instead.
	zapSeeds := katanaSeedURLs(cfg)
	emit(opt, jobID, "info", fmt.Sprintf("ZAP: %d seed URLs (configured targets only)", len(zapSeeds)))
	if len(zapSeeds) == 0 && len(cfg.Targets) > 0 {
		zapSeeds = []string{cfg.Targets[0].BaseURL}
	}
	if len(zapSeeds) == 0 {
		st.Status = model.StepSkipped
		emit(opt, jobID, "warn", "ZAP: no seed URLs (targets), skipping")
		return
	}
	zapDir := filepath.Join(storage.JobRoot(opt.WorkDir, jobID), "zap-out")
	authHeaders := map[string]string{}
	for k, v := range authRes.HeaderInject {
		authHeaders[k] = v
	}
	if len(authHeaders) == 0 && cfg.Auth != nil {
		emit(opt, jobID, "warn", "ZAP Ajax spider: нет Authorization/Cookie заголовков; для JWT SPA приложений сессия в localStorage не будет установлена — используйте cookie-based auth или передайте токен вручную")
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
	feedURLs := zapworker.SelectFeedURLsForZAP(pl.discoveryFeed, zapworker.FeedProbeMax())
	feedProbes := zapworker.BuildFeedRequestorProbes(feedURLs, authHeaders)
	if len(feedProbes) > 0 {
		emit(opt, jobID, "info", fmt.Sprintf("ZAP: %d feed requestor probes from Katana discovery", len(feedProbes)))
	}
	if zapworker.UseAutomation(stepCfg) {
		emit(opt, jobID, "info", fmt.Sprintf("ZAP: Automation Framework (%d seed URLs)", len(zapSeeds)))
		zf, ze, zerr = zapworker.RunAutomation(
			zapSeeds, zapDir, stepCfg.ZAPDockerImage, opt.ConfigFileDir,
			cfg.Scope.Allow, stepCfg, authHeaders, sqlPayloadPath, xssPayloadPath,
			feedProbes, authRes.Context.ContextID, cfg.Noise.Dedupe,
		)
	} else {
		emit(opt, jobID, "info", "ZAP: baseline script (docker)")
		zapBase := zapSeeds[0]
		zf, ze, zerr = zapworker.RunBaseline(zapBase, zapDir, stepCfg.ZAPDockerImage, authHeaders)
	}
	if zerr != nil {
		st.Status = model.StepFailed
		st.Error = zerr.Error()
		emit(opt, jobID, "error", "ZAP: "+st.Error)
		_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "error", "msg": st.Error, "step": string(st.StepType)})
		return
	}
	zapDisc := 0
	for _, f := range zf {
		if f.RuleID == "zap:discovered-url" {
			zapDisc++
		}
	}
	emit(opt, jobID, "info", fmt.Sprintf("ZAP: findings %d (discovered URLs: %d)", len(zf), zapDisc))
	if zapDisc == 0 {
		emit(opt, jobID, "warn", "ZAP: export URL list empty — rebuild dast-worker image; until then only alert URLs feed Nuclei")
	}
	pl.collect(zf, ze, collectOpts{setContextID: true, collectEndpoints: true, addToFeed: true})
	st.Metrics.FindingsRaw = len(zf)
	st.Status = model.StepSucceeded
}

func (pl *pipeline) runWapiti(st *model.JobStep, stepCfg config.ScanStep) {
	opt, cfg, jobID, authRes := pl.opt, pl.cfg, pl.jobID, pl.authRes
	targets := nucleiBasesFromTargets(cfg)
	if len(targets) == 0 {
		st.Status = model.StepSkipped
		emit(opt, jobID, "warn", "Wapiti: no target URLs, skipping")
		return
	}
	wapitiDir := filepath.Join(storage.JobRoot(opt.WorkDir, jobID), "wapiti-out")
	authHeaders := map[string]string{}
	for k, v := range authRes.HeaderInject {
		authHeaders[k] = v
	}
	if len(authHeaders) == 0 && cfg.Auth != nil {
		emit(opt, jobID, "warn", "Wapiti: no Authorization/Cookie headers for target")
	} else if len(authHeaders) > 0 {
		keys := make([]string, 0, len(authHeaders))
		for k := range authHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		emit(opt, jobID, "info", "Wapiti: request headers: "+strings.Join(keys, ", "))
	}
	emit(opt, jobID, "info", fmt.Sprintf("Wapiti: scanning %d start points", len(targets)))
	perTimeout := stepCfg.WapitiTimeout
	if perTimeout <= 0 {
		perTimeout = 300
	}
	locSeen := make(map[string]struct{})
	var wf []model.Finding
	var we []model.Evidence
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		emit(opt, jobID, "info", "Wapiti CLI: "+target)
		tf, te, werr := wapiti.RunCLI(wapiti.CLIOptions{
			Target:                target,
			OutDir:                wapitiDir,
			ScanForce:             stepCfg.WapitiScanForce,
			Timeout:               perTimeout,
			Headers:               authHeaders,
			InsecureSkipTLSVerify: cfg.InsecureSkipTLSVerify,
			ContextID:             authRes.Context.ContextID,
			Dedupe:                cfg.Noise.Dedupe,
		})
		if werr != nil {
			st.Status = model.StepFailed
			st.Error = werr.Error()
			emit(opt, jobID, "error", "Wapiti: "+st.Error)
			_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "error", "msg": st.Error, "step": string(st.StepType)})
			return
		}
		for _, f := range tf {
			key := f.LocationKey
			if key == "" {
				key = f.Title
			}
			if _, ok := locSeen[key]; ok {
				continue
			}
			locSeen[key] = struct{}{}
			wf = append(wf, f)
		}
		we = append(we, te...)
	}
	pl.collect(wf, we, collectOpts{addToFeed: true})
	st.Metrics.FindingsRaw = len(wf)
	st.Status = model.StepSucceeded
	emit(opt, jobID, "info", fmt.Sprintf("Wapiti: findings %d", len(wf)))
}

func (pl *pipeline) runNuclei(st *model.JobStep, stepCfg config.ScanStep) {
	paths := resolveTemplatePaths(pl.opt.ConfigFileDir, stepCfg.TemplatePaths, pl.opt.WorkDir)
	paths = appendSQLiBuiltinTemplatePath(paths, pl.opt.ConfigFileDir)
	paths = appendXSSBuiltinTemplatePath(paths, pl.opt.ConfigFileDir)
	if nucleiUseOfficialCLI(stepCfg) {
		pl.runNucleiCLI(st, stepCfg, paths)
		return
	}
	pl.runNucleiBuiltin(st, stepCfg, paths)
}

func (pl *pipeline) runNucleiCLI(st *model.JobStep, stepCfg config.ScanStep, paths []string) {
	opt, cfg, jobID, authRes := pl.opt, pl.cfg, pl.jobID, pl.authRes
	if opt.SkipNucleiCLI {
		st.Status = model.StepSkipped
		emit(opt, jobID, "info", "Nuclei CLI: skipped (-skip-nuclei or DAST_SKIP_NUCLEI_CLI=1)")
		return
	}
	exist := pl.nucleiCLITemplatePaths(paths)
	if len(exist) == 0 {
		st.Status = model.StepSkipped
		emit(opt, jobID, "info", "Nuclei CLI: no existing template paths, skipping")
		return
	}
	listPath, ok := pl.nucleiCLIListFile(st, stepCfg)
	if !ok {
		return
	}
	hdr := pl.nucleiCLIHeaders()
	emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: шаблонов (путей -t): %d", len(exist)))
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
		return
	}
	emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: matches %d", len(nf)))
	pl.collect(nf, ne, collectOpts{})
	st.Metrics.FindingsRaw = len(nf)
	st.Status = model.StepSucceeded
}

// nucleiCLITemplatePaths resolves existing template paths and appends generated
// SQLi/XSS payload templates when enabled.
func (pl *pipeline) nucleiCLITemplatePaths(paths []string) []string {
	jobRoot := pl.jobRoot
	exist := existingPaths(mergeOfficialNucleiDirs(paths))
	if payloads.SQLiEnabled() {
		if sqliAbs := payloads.SQLiPath(jobRoot); pathExists(sqliAbs) {
			gen := filepath.Join(jobRoot, "artifacts", "payloads", "sqli-nuclei-cli.yaml")
			if err := payloads.WriteNucleiCLITemplate(sqliAbs, gen); err == nil {
				exist = append(exist, gen)
			}
		}
	}
	if payloads.XSSEnabled() {
		if xssAbs := payloads.XSSPath(jobRoot); pathExists(xssAbs) {
			gen := filepath.Join(jobRoot, "artifacts", "payloads", "xss-nuclei-cli.yaml")
			if err := payloads.WriteNucleiXSSCLITemplate(xssAbs, gen); err == nil {
				exist = append(exist, gen)
			}
		}
	}
	return exist
}

// nucleiCLIListFile resolves the targets list file (from config or generated)
// and returns ok=false after setting a failed status if it cannot be produced.
func (pl *pipeline) nucleiCLIListFile(st *model.JobStep, stepCfg config.ScanStep) (string, bool) {
	opt, cfg, jobID := pl.opt, pl.cfg, pl.jobID
	if lf := strings.TrimSpace(stepCfg.NucleiListFile); lf != "" {
		listPath := resolveNucleiListFilePath(opt.WorkDir, jobID, lf)
		fi, statErr := os.Stat(listPath)
		if statErr != nil {
			st.Status = model.StepFailed
			st.Error = fmt.Sprintf("nuclei list file %q: %v", listPath, statErr)
			emit(opt, jobID, "error", "Nuclei CLI: "+st.Error)
			return "", false
		}
		if fi.Size() == 0 {
			st.Status = model.StepFailed
			st.Error = fmt.Sprintf("nuclei list file empty: %s", listPath)
			emit(opt, jobID, "error", "Nuclei CLI: "+st.Error)
			return "", false
		}
		emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: targets из файла %s (%d bytes)", filepath.Base(listPath), fi.Size()))
		return listPath, true
	}
	if stepCfg.NucleiIncludeDiscoveredURLs {
		if len(pl.discoveryFeed) == 0 {
			emit(opt, jobID, "warn", "Nuclei: nucleiIncludeDiscoveredURLs is set but URL feed is empty (put Katana/ZAP before Nuclei in the plan)")
		} else {
			emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: added feed URLs to targets (feed size %d, scope/budget limits apply)", len(pl.discoveryFeed)))
		}
	}
	targetLines := nucleiCLITargetLines(cfg, nucleiBasesFromTargets(cfg), pl.discoveryFeed, stepCfg.NucleiIncludeDiscoveredURLs)
	listPath, werr := writeNucleiTargetsFile(opt.WorkDir, jobID, targetLines)
	if werr != nil {
		st.Status = model.StepFailed
		st.Error = werr.Error()
		emit(opt, jobID, "error", "Nuclei CLI: "+st.Error)
		return "", false
	}
	emit(opt, jobID, "info", fmt.Sprintf("Nuclei CLI: %d targets (file %s)", len(targetLines), filepath.Base(listPath)))
	return listPath, true
}

// nucleiCLIHeaders builds the auth header args and logs which headers are sent.
func (pl *pipeline) nucleiCLIHeaders() []string {
	opt, cfg, jobID, authRes := pl.opt, pl.cfg, pl.jobID, pl.authRes
	var hdr []string
	for k, v := range authRes.HeaderInject {
		hdr = append(hdr, fmt.Sprintf("%s: %s", k, v))
	}
	if len(hdr) == 0 && cfg.Auth != nil {
		emit(opt, jobID, "warn", "Nuclei CLI: без заголовков авторизации к цели")
		return hdr
	}
	if len(hdr) > 0 {
		keys := make([]string, 0, len(authRes.HeaderInject))
		for k := range authRes.HeaderInject {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		emit(opt, jobID, "info", "Nuclei CLI: заголовки: "+strings.Join(keys, ", "))
	}
	return hdr
}

func (pl *pipeline) runNucleiBuiltin(st *model.JobStep, stepCfg config.ScanStep, paths []string) {
	opt, cfg, jobID, jobRoot, authRes := pl.opt, pl.cfg, pl.jobID, pl.jobRoot, pl.authRes
	tpls, terr := nuclei.LoadTemplates(paths)
	if terr != nil || len(tpls) == 0 {
		st.Status = model.StepSkipped
		if terr != nil {
			st.Error = terr.Error()
			emit(opt, jobID, "warn", "Nuclei templates: skipped — "+st.Error)
		} else {
			emit(opt, jobID, "info", "Nuclei templates: no files, skipping")
		}
		return
	}
	if stepCfg.NucleiIncludeDiscoveredURLs {
		if len(pl.discoveryFeed) == 0 {
			emit(opt, jobID, "warn", "Nuclei: nucleiIncludeDiscoveredURLs is set but URL feed is empty (builtin engine only adds new origins)")
		} else {
			emit(opt, jobID, "info", fmt.Sprintf("Nuclei (builtin): added origins from feed to bases (feed paths %d)", len(pl.discoveryFeed)))
		}
	}
	bases := nucleiBuiltinBases(cfg, nucleiBasesFromTargets(cfg), pl.discoveryFeed, stepCfg.NucleiIncludeDiscoveredURLs)
	nf, ne, _ := nuclei.Run(pl.httpClient, bases, tpls, authRes.Context.ContextID, cfg.Noise.Dedupe, jobRoot)
	emit(opt, jobID, "info", fmt.Sprintf("Nuclei templates: matches %d", len(nf)))
	pl.collect(nf, ne, collectOpts{})
	st.Metrics.FindingsRaw = len(nf)
	st.Status = model.StepSucceeded
}

// warnPlanOrdering emits warnings when the discovery feed will be empty because
// of how the plan orders crawl steps relative to Nuclei.
func warnPlanOrdering(opt Options, jobID string, plan []config.ScanStep) {
	var wantDiscoveryFeed, haveDiscovery bool
	nucleiWithFeedIdx := -1
	for i, s := range plan {
		if s.StepType == string(model.StepNucleiTemplates) && s.NucleiIncludeDiscoveredURLs {
			wantDiscoveryFeed = true
			nucleiWithFeedIdx = i
		}
		if s.StepType == string(model.StepKatana) || s.StepType == string(model.StepHttpx) || s.StepType == string(model.StepZAPBaseline) {
			haveDiscovery = true
		}
	}
	if wantDiscoveryFeed && !haveDiscovery {
		emit(opt, jobID, "warn", "Nuclei: nucleiIncludeDiscoveredURLs is set but the plan has no katana or zapBaseline — discovery feed will stay empty")
	}
	if nucleiWithFeedIdx < 0 {
		return
	}
	for i, s := range plan {
		if i <= nucleiWithFeedIdx {
			continue
		}
		if s.StepType == string(model.StepKatana) || s.StepType == string(model.StepZAPBaseline) {
			emit(opt, jobID, "warn", "Plan order: Nuclei with URL feed runs before katana/zapBaseline — feed is empty when Nuclei runs; reorder steps (crawl/ZAP first)")
			return
		}
	}
}
