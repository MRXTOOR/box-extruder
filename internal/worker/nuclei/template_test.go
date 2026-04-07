package nuclei

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/box-extruder/dast/internal/config"
)

func TestLoadTemplates(t *testing.T) {
	tpls, err := LoadTemplates([]string{filepath.Join("testdata", "sample.yaml")})
	if err != nil || len(tpls) != 1 || tpls[0].ID != "utest-match" {
		t.Fatalf("%v %+v", err, tpls)
	}
}

func TestRun_againstServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hello" {
			_, _ = w.Write([]byte("prefix HELLO_WORLD suffix"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	tpls, err := LoadTemplates([]string{filepath.Join("testdata", "sample.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	dedupe := config.DedupeConfig{LocationKey: "endpoint+method+paramsNormalized", ParamNormalization: "basic"}
	fs, ev, err := Run(nil, []string{srv.URL}, tpls, "ctx1", dedupe, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || len(ev) != 1 {
		t.Fatalf("findings=%d ev=%d", len(fs), len(ev))
	}
}
