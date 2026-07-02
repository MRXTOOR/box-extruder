package zap

import "testing"

func TestSelectFeedURLsForZAP_Priority(t *testing.T) {
	feed := []string{
		"https://app.example/static/app.js",
		"https://app.example/app/home",
		"https://app.example/api/v1/users",
		"https://app.example/%PUBLIC_URL%/x",
	}
	out := SelectFeedURLsForZAP(feed, 2)
	if len(out) != 2 {
		t.Fatalf("want 2, got %d: %v", len(out), out)
	}
	if out[0] != "https://app.example/api/v1/users" {
		t.Fatalf("api first: %v", out)
	}
}

func TestBuildFeedRequestorProbes(t *testing.T) {
	probes := BuildFeedRequestorProbes([]string{"https://app.example/a"}, map[string]string{"Authorization": "Bearer x"})
	if len(probes) != 1 {
		t.Fatalf("probes: %v", probes)
	}
	if probes[0]["method"] != "GET" {
		t.Fatalf("method: %v", probes[0]["method"])
	}
}
