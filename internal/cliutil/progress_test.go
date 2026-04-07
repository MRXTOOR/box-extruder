package cliutil

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestDemoProgressSink(t *testing.T) {
	var buf bytes.Buffer
	sink := DemoProgressSink(&buf)
	sink(time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC), "info", "test", nil)
	s := buf.String()
	if !strings.Contains(s, "INFO") || !strings.Contains(s, "test") {
		t.Fatal(s)
	}
}
