package cliutil

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/box-extruder/dast/internal/runner"
)

// DemoProgressSink writes human-readable lines to w (e.g. os.Stderr) for live demo.
func DemoProgressSink(w io.Writer) runner.ProgressSink {
	return func(ts time.Time, level, msg string, _ map[string]string) {
		_, _ = fmt.Fprintf(w, "[%s] %-5s  %s\n", ts.In(time.Local).Format("15:04:05"), strings.ToUpper(level), msg)
	}
}
