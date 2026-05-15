package main

import (
	"context"
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

	rdb, err := queue.Connect(queue.Config{Host: redisHost, Port: redisPort, Password: redisPass})
	if err != nil {
		log.Fatalf("Redis connect: %v", err)
	}
	defer rdb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			if fmt.Sprint(r) == "canceled" {
				db.UpdateScanStatus(ctx, pool, job.JobID, "CANCELLED")
				return
			}
			db.UpdateScanStatus(ctx, pool, job.JobID, "FAILED")
		}
	}()

	if err := db.UpdateScanStatus(ctx, pool, job.JobID, "RUNNING"); err != nil {
		log.Printf("Failed to update status to RUNNING: %v", err)
		return
	}

	var yamlData []byte
	if strings.TrimSpace(job.ConfigYAML) != "" {
		yamlData = []byte(job.ConfigYAML)
	} else {
		cfg := buildConfig(job)
		var err error
		yamlData, err = yaml.Marshal(cfg)
		if err != nil {
			log.Printf("Failed to marshal config: %v", err)
			db.UpdateScanStatus(ctx, pool, job.JobID, "FAILED")
			return
		}
	}

	parsedCfg, err := config.ParseScanAsCode(yamlData)
	if err != nil {
		log.Printf("Failed to parse config: %v", err)
		db.UpdateScanStatus(ctx, pool, job.JobID, "FAILED")
		return
	}

	runnerOpts := runner.Options{
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
		OnProgress: func(ts time.Time, level, msg string, fields map[string]string) {
			if canceled, _ := queue.GetCancelFlag(ctx, rdb, job.JobID); canceled {
				log.Printf("Job %s canceled during execution", job.JobID)
				db.UpdateScanStatus(ctx, pool, job.JobID, "CANCELLED")
				panic("canceled")
			}
		},
	}

	_, err = runner.Run(runnerOpts)
	if err != nil {
		if canceled, _ := queue.GetCancelFlag(ctx, rdb, job.JobID); canceled {
			log.Printf("Job %s was canceled", job.JobID)
			db.UpdateScanStatus(ctx, pool, job.JobID, "CANCELLED")
			return
		}
		log.Printf("Job %s failed: %v", job.JobID, err)
		db.UpdateScanStatus(ctx, pool, job.JobID, "FAILED")
		return
	}

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
			Evidence:    evidence,
		})
	}
	return out
}

func buildConfig(job *queue.JobMessage) *config.ScanAsCode {
	cfg := config.DefaultScanAsCode()
	cfg.Job.Name = job.JobID
	cfg.Targets = []config.Target{
		{
			Type:        "web",
			BaseURL:     job.TargetURL,
			StartPoints: []string{job.TargetURL},
		},
	}
	cfg.Scope.Allow = []string{".*"}
	cfg.Scope.Deny = nil
	cfg.Scan.Plan = []config.ScanStep{
		{StepType: "katana", Enabled: true},
		{StepType: "zapBaseline", Enabled: true, ZAPAutomationFramework: true, ZAPSpiderTraditional: true},
		{StepType: "nucleiTemplates", Enabled: true, TemplatePaths: []string{"templates/example-banner.yaml"}},
	}
	return &cfg
}
