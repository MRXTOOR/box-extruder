package payloads

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendSQLiSeedURLs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sqli.txt")
	if err := os.WriteFile(p, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seeds := []string{"http://127.0.0.1:3000/"}
	t.Setenv("DAST_KATANA_SQLI_SEED_MAX", "10")
	out, err := AppendSQLiSeedURLs(seeds, "http://127.0.0.1:3000/", "q", p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 2 {
		t.Fatalf("got %d", len(out))
	}
}

func TestSQLiEnabled(t *testing.T) {
	t.Setenv("DAST_SQLI_PAYLOADS", "0")
	if SQLiEnabled() {
		t.Fatal()
	}
	t.Setenv("DAST_SQLI_PAYLOADS", "")
	if !SQLiEnabled() {
		t.Fatal()
	}
}
