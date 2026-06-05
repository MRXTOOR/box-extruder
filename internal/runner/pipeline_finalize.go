package runner

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/box-extruder/dast/internal/report"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/google/uuid"
)

// enqueueNucleiFollowUp optionally schedules a separate Nuclei job seeded with
// the URLs discovered during this scan.
func (pl *pipeline) enqueueNucleiFollowUp() {
	opt, cfg, jobID := pl.opt, pl.cfg, pl.jobID
	if !shouldEnqueueNucleiFollowUp(cfg, opt) {
		return
	}
	lines := collectNucleiSeedLines(cfg, pl.discoveryFeed)
	seedPath, werr := writeNucleiKatanaSeedsFile(opt.WorkDir, jobID, lines)
	if werr != nil {
		emit(opt, jobID, "warn", "nuclei follow-up: не удалось записать URL: "+werr.Error())
		return
	}
	emit(opt, jobID, "info", fmt.Sprintf("nuclei follow-up: сохранено %d URL в %s", len(lines), filepath.Base(seedPath)))
	followID := uuid.NewString()
	yamlBytes, ferr := buildNucleiFollowUpYAML(cfg, seedPath, followID)
	if ferr != nil {
		emit(opt, jobID, "warn", "nuclei follow-up: сборка YAML: "+ferr.Error())
		return
	}
	parentTarget := ""
	if len(cfg.Targets) > 0 {
		parentTarget = strings.TrimSpace(cfg.Targets[0].BaseURL)
	}
	req := FollowUpEnqueueRequest{
		JobID:      followID,
		UserID:     strings.TrimSpace(opt.UserID),
		TargetURL:  parentTarget + " [Nuclei]",
		ConfigYAML: yamlBytes,
		ConfigHash: storage.ConfigHashSHA256(yamlBytes),
	}
	switch {
	case req.UserID == "":
		emit(opt, jobID, "warn", "nuclei follow-up: userId пуст — задача в очередь не ставится")
	case opt.OnFollowUpEnqueue == nil:
		emit(opt, jobID, "warn", "nuclei follow-up: колбэк очереди не задан")
	default:
		if err := opt.OnFollowUpEnqueue(req); err != nil {
			emit(opt, jobID, "error", "nuclei follow-up: очередь: "+err.Error())
		} else {
			emit(opt, jobID, "info", "nuclei follow-up: в очереди отдельная задача jobId="+followID)
		}
	}
}

// finalizeAndReport links evidence, persists findings, renders reports and marks
// the job done. started is the job start time used in the report header.
func (pl *pipeline) finalizeAndReport(started time.Time) error {
	opt, cfg, jobID, job := pl.opt, pl.cfg, pl.jobID, pl.job

	for i := range pl.rawFindings {
		for _, eid := range pl.rawFindings[i].EvidenceRefs {
			if ev, ok := pl.evidenceByID[eid]; ok {
				ev.ContextID = pl.authRes.Context.ContextID
				pl.evidenceByID[eid] = ev
			}
		}
	}
	for _, ev := range pl.evidenceByID {
		_ = storage.WriteEvidence(opt.WorkDir, jobID, &ev)
	}
	if err := storage.WriteFindingsJSON(opt.WorkDir, jobID, "findings-raw.json", pl.rawFindings); err != nil {
		return err
	}
	emit(opt, jobID, "info", fmt.Sprintf("Raw findings written: %d", len(pl.rawFindings)))

	final := noise.Apply(*cfg, pl.rawFindings, pl.evidenceByID)
	if err := storage.WriteFindingsJSON(opt.WorkDir, jobID, "findings-final.json", final); err != nil {
		return err
	}
	emit(opt, jobID, "info", fmt.Sprintf("After noise control: %d findings", len(final)))

	endpoints := pl.reportEndpoints()
	if err := pl.writeReports(final, endpoints, started); err != nil {
		return err
	}

	job.Status = model.JobSucceeded
	for _, st := range job.Steps {
		if st.Status == model.StepFailed {
			job.Status = model.JobPartialSuccess
		}
	}
	if len(endpoints) > 0 {
		job.ScannedEndpoints = endpoints
	}
	finishJob(opt.WorkDir, job)
	emit(opt, jobID, "info", "Done, job status: "+string(job.Status))
	_ = storage.AppendEvent(opt.WorkDir, jobID, map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": "info", "msg": "job finished", "status": string(job.Status)})
	return nil
}

// reportEndpoints picks the endpoint list for the report, preferring the full
// discovery feed and writing it to disk when present.
func (pl *pipeline) reportEndpoints() []string {
	opt, jobID := pl.opt, pl.jobID
	if len(pl.discoveryFeed) > 0 {
		pl.job.DiscoveryURLsCount = len(pl.discoveryFeed)
		_ = storage.WriteDiscoveredURLsTxt(opt.WorkDir, jobID, pl.discoveryFeed)
		emit(opt, jobID, "info", fmt.Sprintf("Discovery: %d URLs written to reports/discovered_urls.txt", len(pl.discoveryFeed)))
		return pl.discoveryFeed
	}
	emit(opt, jobID, "warn", "Discovery feed empty — endpoints list will only include URLs from crawl evidence")
	return pl.scannedEndpoints
}

// writeReports renders HTML, DOCX and PDF (enterprise template) plus endpoints list.
func (pl *pipeline) writeReports(final []model.Finding, endpoints []string, started time.Time) error {
	opt, cfg, jobID := pl.opt, pl.cfg, pl.jobID
	baseURL := ""
	if len(cfg.Targets) > 0 {
		baseURL = cfg.Targets[0].BaseURL
	}
	preset := cfg.Scan.Preset
	if preset == "" {
		preset = "custom"
	}
	reportData := report.Data{
		JobName:           cfg.Job.Name,
		BaseURL:           baseURL,
		Preset:            preset,
		Started:           started,
		Finished:          time.Now().UTC(),
		Findings:          final,
		Evidence:          pl.evidenceByID,
		IncludeEvidence:   cfg.ReportIncludeEvidence(),
		EvidenceThreshold: cfg.Budgets.Verification.EvidenceThreshold,
		ScannedEndpoints:  endpoints,
	}
	root := storage.JobRoot(opt.WorkDir, jobID)
	reportsDir := filepath.Join(root, "reports")
	ref := report.ResolveEnterpriseReferenceDoc("", opt.WorkDir)
	if cfg.Outputs.Docx != nil && cfg.Outputs.Docx.TemplateRef != "" {
		ref = report.ResolveEnterpriseReferenceDoc(cfg.Outputs.Docx.TemplateRef, opt.WorkDir)
	}
	if err := report.WriteScanReports(reportData, reportsDir, ref); err != nil {
		emit(opt, jobID, "warn", "Reports: "+err.Error())
	} else {
		emit(opt, jobID, "info", "Reports saved: HTML, DOCX, PDF (reports/)")
	}
	_ = storage.WriteEndpointsTxt(opt.WorkDir, jobID, endpoints)
	return nil
}
