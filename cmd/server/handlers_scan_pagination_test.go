package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPaginateStringList(t *testing.T) {
	all := []string{"https://a/1", "https://a/2", "https://b/3", "https://b/4"}
	items, total := paginateStringList(all, 2, 0, "b")
	if total != 2 || len(items) != 2 {
		t.Fatalf("filter b: total=%d items=%v", total, items)
	}
	items, total = paginateStringList(all, 2, 1, "")
	if total != 4 || len(items) != 2 || items[0] != "https://a/2" {
		t.Fatalf("page 2: total=%d items=%v", total, items)
	}
}

func TestParsePagination(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?limit=999&offset=5", nil)
	limit, offset := parsePagination(req)
	if limit != 200 || offset != 5 {
		t.Fatalf("limit=%d offset=%d", limit, offset)
	}
}
