package zap

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/box-extruder/dast/internal/noise"
)

// FeedProbeMax returns the cap for Katana→ZAP requestor probes (default 500).
func FeedProbeMax() int {
	if v := strings.TrimSpace(os.Getenv("DAST_ZAP_FEED_PROBE_MAX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 500
}

// SelectFeedURLsForZAP filters garbage/attack URLs and returns up to max probes,
// prioritizing /api/ paths and page-like URLs.
func SelectFeedURLsForZAP(feed []string, max int) []string {
	if max <= 0 {
		max = FeedProbeMax()
	}
	type candidate struct {
		url      string
		priority int
		order    int
	}
	var cands []candidate
	seen := make(map[string]struct{})
	order := 0
	for _, raw := range feed {
		raw = strings.TrimSpace(raw)
		if raw == "" || noise.IsGarbageDiscoveryURL(raw) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		pri := 0
		if u, err := url.Parse(raw); err == nil {
			lp := strings.ToLower(u.Path)
			if strings.Contains(lp, "/api/") {
				pri = 2
			} else if isPageLikeURL(raw) {
				pri = 1
			}
		}
		cands = append(cands, candidate{url: raw, priority: pri, order: order})
		order++
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].priority != cands[j].priority {
			return cands[i].priority > cands[j].priority
		}
		return cands[i].order < cands[j].order
	})
	out := make([]string, 0, max)
	for _, c := range cands {
		if len(out) >= max {
			break
		}
		out = append(out, c.url)
	}
	return out
}

// BuildFeedRequestorProbes builds GET requestor jobs for ZAP passive analysis.
func BuildFeedRequestorProbes(urls []string, authHeaders map[string]string) []map[string]any {
	names := make([]string, 0, len(authHeaders))
	for k := range authHeaders {
		names = append(names, k)
	}
	sort.Strings(names)
	var hdrs []string
	for _, k := range names {
		hdrs = append(hdrs, fmt.Sprintf("%s: %s", k, authHeaders[k]))
	}
	var reqs []map[string]any
	for i, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		m := map[string]any{
			"url":    raw,
			"method": "GET",
			"name":   fmt.Sprintf("feed-%d", i+1),
		}
		if len(hdrs) > 0 {
			m["headers"] = hdrs
		}
		reqs = append(reqs, m)
	}
	return reqs
}
