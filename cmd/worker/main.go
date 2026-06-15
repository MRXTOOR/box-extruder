package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/box-extruder/dast/internal/config"
	"github.com/box-extruder/dast/internal/enterprise/db"
	"github.com/box-extruder/dast/internal/enterprise/queue"
	"github.com/box-extruder/dast/internal/model"
	"github.com/box-extruder/dast/internal/noise"
	"github.com/box-extruder/dast/internal/runner"
	"github.com/box-extruder/dast/internal/storage"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

func main() {
	flag.StringVar(&dbHost, "db-host", "postgres", "PostgreSQL host")
	flag.IntVar(&dbPort, "db-port", 5432, "PostgreSQL port")
	flag.StringVar(&dbUser, "db-user", "dast", "PostgreSQL user")
	flag.StringVar(&dbPass, "db-pass", "dast", "PostgreSQL password")
	flag.StringVar(&dbName, "db-name", "dast", "PostgreSQL database")

	flag.StringVar(&redisHost, "redis-host", "redis", "Redis host")
	flag.IntVar(&redisPort, "redis-port", 6379, "Redis port")
	flag.StringVar(&redisPass, "redis-pass", "", "Redis password")

	flag.StringVar(&workDir, "work-dir", "/workspace/work", "Work directory")
	flag.Parse()

	pool, err := db.Connect(db.Config{
		Host: dbHost, Port: dbPort, User: dbUser, Password: dbPass, DBName: dbName,
	})
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		log.Fatalf("DB migrations: %v", err)
	}

	rdb, err := queue.Connect(queue.Config{Host: redisHost, Port: redisPort, Password: redisPass})
	if err != nil {
		log.Fatalf("Redis connect: %v", err)
	}
	defer rdb.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	workerConcurrency := getWorkerConcurrency()
	log.Printf("Worker started, waiting for jobs (concurrency=%d)...", workerConcurrency)

	var workersWG sync.WaitGroup
	for i := 0; i < workerConcurrency; i++ {
		workersWG.Add(1)
		workerID := i + 1
		go func(id int) {
			defer workersWG.Done()
			runWorkerLoop(ctx, pool, rdb, workDir, id)
		}(workerID)
	}

	<-sigCh
	log.Println("Shutting down...")
	cancel()
	workersWG.Wait()
}

var dbHost, dbUser, dbPass, dbName string
var dbPort int
var redisHost, redisPass string
var redisPort int
var workDir string

func getWorkerConcurrency() int {
	// By default run up to 4 scans in parallel.
	raw := strings.TrimSpace(os.Getenv("DAST_WORKER_CONCURRENCY"))
	if raw == "" {
		return 4
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		log.Printf("Invalid DAST_WORKER_CONCURRENCY=%q, fallback to 4", raw)
		return 4
	}
	if v > 16 {
		log.Printf("DAST_WORKER_CONCURRENCY=%d is too high, capping to 16", v)
		return 16
	}
	return v
}

func runWorkerLoop(ctx context.Context, pool *db.Pool, rdb *redis.Client, workDir string, workerID int) {
	for {
		job, err := queue.Dequeue(ctx, rdb, 5*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, redis.Nil) {
				// Empty queue: BRPOP timed out, this is the normal idle path.
				continue
			}
			// Real Redis or message-decode failure: log it instead of silently
			// dropping the job, and back off to avoid a hot error loop.
			log.Printf("Worker %d: dequeue error: %v", workerID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}

		canceled, err := queue.GetCancelFlag(ctx, rdb, job.JobID)
		if err != nil {
			log.Printf("Worker %d warning: failed to check cancel flag: %v", workerID, err)
		}
		if canceled {
			log.Printf("Worker %d: job %s was canceled before start", workerID, job.JobID)
			_ = queue.ClearCancelFlag(ctx, rdb, job.JobID)
			_ = db.UpdateScanStatus(ctx, pool, job.JobID, "CANCELLED")
			continue
		}

		log.Printf("Worker %d: processing job %s for target %s", workerID, job.JobID, job.TargetURL)
		processJob(ctx, pool, rdb, workDir, job)
	}
}

func processJob(ctx context.Context, pool *db.Pool, rdb *redis.Client, workDir string, job *queue.JobMessage) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Job %s panic: %v", job.JobID, r)
			db.UpdateScanStatus(ctx, pool, job.JobID, "FAILED")
		}
	}()

	if err := db.UpdateScanStatus(ctx, pool, job.JobID, "RUNNING"); err != nil {
		log.Printf("Failed to update status to RUNNING: %v", err)
		return
	}

	yamlData, parsedCfg, err := prepareJobConfig(job)
	if err != nil {
		log.Printf("Job %s config: %v", job.JobID, err)
		db.UpdateScanStatus(ctx, pool, job.JobID, "FAILED")
		return
	}

	// Per-job context: canceled when the user requests cancellation (observed via
	// the Redis cancel flag) or when the worker shuts down. The runner checks it
	// between pipeline steps and returns runner.ErrCanceled.
	jobCtx, cancelJob := context.WithCancel(ctx)
	defer cancelJob()
	go watchCancelFlag(jobCtx, rdb, job.JobID, cancelJob)

	runnerOpts := runner.Options{
		Ctx:           jobCtx,
		WorkDir:       workDir,
		ConfigYAML:    yamlData,
		Config:        parsedCfg,
		JobID:         job.JobID,
		ConfigFileDir: "/workspace",
		UserID:        job.UserID,
		OnFollowUpEnqueue: func(req runner.FollowUpEnqueueRequest) error {
			if _, err := db.CreateScan(ctx, pool, req.UserID, req.JobID, req.TargetURL, req.ConfigHash); err != nil {
				return fmt.Errorf("create scan (nuclei follow-up): %w", err)
			}
			return queue.Enqueue(ctx, rdb, queue.JobMessage{
				JobID:      req.JobID,
				UserID:     req.UserID,
				TargetURL:  req.TargetURL,
				ConfigYAML: string(req.ConfigYAML),
				ConfigHash: req.ConfigHash,
			})
		},
	}

	if _, err := runner.Run(runnerOpts); err != nil {
		handleRunError(ctx, pool, rdb, job, err)
		return
	}
	finalizeJob(ctx, pool, workDir, job)
}

// prepareJobConfig resolves the effective scan YAML (from the job message or a
// built config) and parses it.
func prepareJobConfig(job *queue.JobMessage) ([]byte, *config.ScanAsCode, error) {
	yamlData := []byte(job.ConfigYAML)
	if strings.TrimSpace(job.ConfigYAML) == "" {
		out, err := yaml.Marshal(buildConfig(job))
		if err != nil {
			return nil, nil, fmt.Errorf("marshal config: %w", err)
		}
		yamlData = out
	}
	parsedCfg, err := config.ParseScanAsCode(yamlData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	return yamlData, parsedCfg, nil
}

// handleRunError maps a runner error to CANCELLED or FAILED scan status.
func handleRunError(ctx context.Context, pool *db.Pool, rdb *redis.Client, job *queue.JobMessage, err error) {
	if errors.Is(err, runner.ErrCanceled) || isJobCanceled(ctx, rdb, job.JobID) {
		log.Printf("Job %s was canceled", job.JobID)
		db.UpdateScanStatus(ctx, pool, job.JobID, "CANCELLED")
		return
	}
	log.Printf("Job %s failed: %v", job.JobID, err)
	db.UpdateScanStatus(ctx, pool, job.JobID, "FAILED")
}

// finalizeJob records the terminal scan status and persists findings to the DB.
func finalizeJob(ctx context.Context, pool *db.Pool, workDir string, job *queue.JobMessage) {
	finalStatus := "SUCCEEDED"
	if j, err := storage.ReadJob(workDir, job.JobID); err == nil {
		if s := strings.TrimSpace(string(j.Status)); s != "" {
			finalStatus = s
		}
	}
	if err := db.UpdateScanStatus(ctx, pool, job.JobID, finalStatus); err != nil {
		log.Printf("Failed to update status to %s: %v", finalStatus, err)
	}
	if err := persistFindingsToDB(ctx, pool, workDir, job.JobID); err != nil {
		log.Printf("Job %s: persist findings to DB: %v", job.JobID, err)
	}
	log.Printf("Job %s completed with status %s", job.JobID, finalStatus)
}

// watchCancelFlag polls the Redis cancel flag and cancels the job context when
// the user requests cancellation. It exits when ctx is done (job finished).
func watchCancelFlag(ctx context.Context, rdb *redis.Client, jobID string, cancel context.CancelFunc) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if canceled, _ := queue.GetCancelFlag(ctx, rdb, jobID); canceled {
				log.Printf("Job %s: cancel flag observed, stopping", jobID)
				cancel()
				return
			}
		}
	}
}

func isJobCanceled(ctx context.Context, rdb *redis.Client, jobID string) bool {
	canceled, _ := queue.GetCancelFlag(ctx, rdb, jobID)
	return canceled
}

func persistFindingsToDB(ctx context.Context, pool *db.Pool, workDir, jobID string) error {
	scan, err := db.GetScanByJobID(ctx, pool, jobID)
	if err != nil {
		return fmt.Errorf("scan row: %w", err)
	}
	raw, err := storage.LoadFindingsJSON(workDir, jobID, "findings-final.json")
	if err != nil {
		return fmt.Errorf("load findings-final.json: %w", err)
	}
	items := findingsToDBRows(scan.ID, raw)
	return db.ReplaceFindingsForScan(ctx, pool, scan.ID, items)
}

func findingsToDBRows(scanID string, raw []model.Finding) []db.Finding {
	out := make([]db.Finding, 0, len(raw))
	for _, f := range raw {
		name := strings.TrimSpace(f.Title)
		if name == "" {
			name = strings.TrimSpace(f.RuleID)
		}
		if name == "" {
			name = "finding"
		}
		desc := strings.TrimSpace(f.Description)
		if desc == "" {
			desc = f.LocationKey
		}
		evidence := map[string]any{
			"findingId":       f.FindingID,
			"ruleId":          f.RuleID,
			"category":        f.Category,
			"locationKey":     f.LocationKey,
			"lifecycleStatus": string(f.LifecycleStatus),
			"confidence":      f.Confidence,
			"evidenceRefs":    f.EvidenceRefs,
		}
		out = append(out, db.Finding{
			ScanID:      scanID,
			Severity:    string(f.Severity),
			Name:        name,
			Description: desc,
			EndpointPath: noise.EndpointURLFromLocationKey(f.LocationKey),
			Evidence:    evidence,
		})
	}
	return out
}

func buildConfig(job *queue.JobMessage) *config.ScanAsCode {
	cfg := config.DefaultScanAsCode()
	cfg.Job.Name = job.JobID
	target := strings.TrimSpace(job.TargetURL)
	cfg.Targets = []config.Target{
		{
			Type:        "web",
			BaseURL:     target,
			StartPoints: []string{target},
		},
	}
	cfg.Scope.Allow = []string{".*"}
	cfg.Scope.Deny = nil
	cfg.Budgets.Discovery.MaxDepth = 6
	cfg.Budgets.Discovery.MaxURLs = 3000
	cfg.Budgets.Discovery.DurationCrawlSecs = 120
	cfg.Budgets.Discovery.PreserveQuery = true
	cfg.Scan.Plan = []config.ScanStep{
		{
			StepType:        "katana",
			Enabled:         true,
			KatanaDepth:     6,
			KatanaHeadless:  true,
			KatanaExtraArgs: []string{"-jc"},
		},
		{
			StepType:               "zapBaseline",
			Enabled:                true,
			ZAPAutomationFramework: true,
			ZAPSpiderTraditional:   true,
			ZAPSpiderAjax:          true,
			ZAPMaxSpiderMinutes:    15,
			ZAPPassiveWaitSeconds:  180,
		},
		{
			StepType:        "wapiti",
			Enabled:         true,
			WapitiScanForce: "normal",
			WapitiTimeout:   900,
		},
		{
			StepType:                    "nucleiTemplates",
			Enabled:                     true,
			NucleiEngine:                "cli",
			TemplatePaths:               []string{"/opt/nuclei-templates"},
			NucleiIncludeDiscoveredURLs: true,
			NucleiRateLimit:             50,
		},
	}
	return &cfg
}
