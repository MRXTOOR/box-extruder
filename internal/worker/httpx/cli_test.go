package httpx

import "testing"

func TestParseJSONL(t *testing.T) {
	raw := []byte(`{"url":"https://example.com","status_code":200,"title":"Home","tech":["nginx"]}
{"url":"https://example.com/missing","status_code":404,"title":""}`)
	rows := parseJSONL(raw)
	if len(rows) != 2 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0].StatusCode != 200 || rows[0].Title != "Home" {
		t.Fatalf("row0: %+v", rows[0])
	}
}

func TestFilterFeedURLs(t *testing.T) {
	feed := []string{
		"https://app.example/api/x",
		"https://app.example/%PUBLIC_URL%/y",
		"https://app.example/page",
	}
	out := FilterFeedURLs(feed)
	if len(out) != 2 {
		t.Fatalf("filtered: %v", out)
	}
}
