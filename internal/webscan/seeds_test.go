package webscan

import "testing"

func TestInferStartPointsFromLoginURL(t *testing.T) {
	got := inferStartPointsFromLoginURL("https://sfera.release.dev.sfera-t1.ru/app/ppau/api/auth/login")
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "https://sfera.release.dev.sfera-t1.ru/app/ppau/" {
		t.Fatalf("got[0]=%q", got[0])
	}
	if got[1] != "https://sfera.release.dev.sfera-t1.ru/app/ppau" {
		t.Fatalf("got[1]=%q", got[1])
	}
	if infer := inferStartPointsFromLoginURL("https://example.com/login"); len(infer) != 0 {
		t.Fatalf("expected none for non-/api/ login, got %v", infer)
	}
}
