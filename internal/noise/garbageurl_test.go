package noise

import "testing"

func TestIsGarbageDiscoveryURL(t *testing.T) {
	garbage := []string{
		"https://app.example/%PUBLIC_URL%/static/js/main.js",
		"https://app.example/%25%25PUBLIC%25%25URL%25%25",
		"https://app.example/manifest.json",
		"https://app.example/static/js/bundle.js",
		"https://app.example/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
	}
	for _, u := range garbage {
		if !IsGarbageDiscoveryURL(u) {
			t.Errorf("expected garbage: %s", u)
		}
	}
	ok := []string{
		"https://app.example/app/dashboard",
		"https://app.example/api/v1/users",
	}
	for _, u := range ok {
		if IsGarbageDiscoveryURL(u) {
			t.Errorf("expected ok: %s", u)
		}
	}
}
