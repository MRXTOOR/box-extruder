package noise

import (
	"testing"

	"github.com/box-extruder/dast/internal/model"
)

func TestHTTPEvidenceMeetsThreshold_low(t *testing.T) {
	ev := model.Evidence{
		Type: model.EvidenceHTTPRequestResponse,
		Payload: model.HTTPRequestResponsePayload{
			Method: "GET",
			URL:    "http://x/",
		},
	}
	if !HTTPEvidenceMeetsThreshold(ev, "low") {
		t.Fatal("expected low to pass with URL")
	}
	ev2 := model.Evidence{Type: model.EvidenceHTTPRequestResponse, Payload: model.HTTPRequestResponsePayload{Method: "GET"}}
	if HTTPEvidenceMeetsThreshold(ev2, "low") {
		t.Fatal("expected fail without URL")
	}
}

func TestHTTPEvidenceMeetsThreshold_medium(t *testing.T) {
	base := model.HTTPRequestResponsePayload{Method: "GET", URL: "http://x/"}
	ev := model.Evidence{Type: model.EvidenceHTTPRequestResponse, Payload: base}
	if HTTPEvidenceMeetsThreshold(ev, "medium") {
		t.Fatal("medium needs status or body snippet")
	}
	ev.Payload = model.HTTPRequestResponsePayload{Method: "GET", URL: "http://x/", StatusCode: 200}
	if !HTTPEvidenceMeetsThreshold(ev, "medium") {
		t.Fatal("status should satisfy medium")
	}
}

func TestFindingEvidenceQualityLabel(t *testing.T) {
	f := model.Finding{
		EvidenceRefs: []string{"e1"},
	}
	ev := map[string]model.Evidence{
		"e1": {
			Type: model.EvidenceHTTPRequestResponse,
			Payload: model.HTTPRequestResponsePayload{
				Method: "GET", URL: "http://x/", StatusCode: 200,
				ResponseBodySnippet: "0123456789abcdef",
				ResponseHeaders:     map[string]string{"x": "y"},
			},
		},
	}
	if FindingEvidenceQualityLabel(f, ev, "high") != "sufficient" {
		t.Fatal()
	}
	if FindingEvidenceQualityLabel(f, ev, "medium") != "sufficient" {
		t.Fatal()
	}
}
