package discovery

import "testing"

func TestCandidateAuthURLs_explicitOnly(t *testing.T) {
	got := CandidateAuthURLs("https://app.example.com", "https://app.example.com/api/login", false)
	if len(got) != 1 || got[0] != "https://app.example.com/api/login" {
		t.Fatalf("got %v", got)
	}
}

func TestCandidateAuthURLs_commonAPIPaths(t *testing.T) {
	got := CandidateAuthURLs("https://app.example.com", "", false)
	want := "https://app.example.com/api/v1/auth/login"
	found := false
	for _, u := range got {
		if u == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q in %v", want, got)
	}
}

func TestCandidateAuthURLs_loginTarget(t *testing.T) {
	target := "https://app.example.com/api/v1/auth/login"
	got := CandidateAuthURLs(target, "", false)
	for _, u := range got {
		if u == target {
			return
		}
	}
	t.Fatalf("expected %q in %v", target, got)
}
