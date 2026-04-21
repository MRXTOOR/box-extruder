package cliutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/box-extruder/dast/internal/storage"
)

// ResolveJobID returns job id from spec "last" or a concrete uuid/directory name.
func ResolveJobID(workDir, spec string) (string, error) {
	if spec == "last" || spec == "" {
		return storage.LatestJobID(workDir)
	}
	return spec, nil
}

// PrintOrchestratorLog prints logs/orchestrator.log; if follow, polls for new lines.
func PrintOrchestratorLog(w io.Writer, workDir, jobID string, follow bool, poll time.Duration) error {
	path := storage.OrchestratorLogPath(workDir, jobID)
	if !follow {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	var offset int64
	for {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				time.Sleep(poll)
				continue
			}
			return err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if st.Size() < offset {
			offset = 0
		}
		if st.Size() > offset {
			_, _ = f.Seek(offset, io.SeekStart)
			n, _ := io.Copy(w, f)
			offset += n
		}
		f.Close()
		time.Sleep(poll)
	}
}

// PrintDemoBanner writes artifact paths after a run (Russian, for presentation).
func PrintDemoBanner(w io.Writer, workDir, jobID string) {
	root := storage.JobRoot(workDir, jobID)
	_, _ = fmt.Fprintf(w, "\n--- Demo: job artifacts ---\n")
	_, _ = fmt.Fprintf(w, "  Events:            %s\n", filepath.Join(root, "events", "events.jsonl"))
	_, _ = fmt.Fprintf(w, "  Orchestrator log:  %s\n", storage.OrchestratorLogPath(workDir, jobID))
	_, _ = fmt.Fprintf(w, "  Findings:          %s\n", filepath.Join(root, "findings", "findings-final.json"))
	_, _ = fmt.Fprintf(w, "  Report MD:         %s\n", filepath.Join(root, "reports", "report.md"))
	_, _ = fmt.Fprintf(w, "  Report Word/LO:    %s%s\n",
		filepath.Join(root, "reports", "report.html"),
		filepath.Join(root, "reports", "report.docx"))
	_, _ = fmt.Fprintf(w, "Tail log: scan logs last -work %s -f\n\n", workDir)
}
