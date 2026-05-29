package noise

import "testing"

func TestEndpointURLFromLocationKey(t *testing.T) {
	tests := []struct {
		name        string
		locationKey string
		want        string
	}{
		{
			name:        "full url with query",
			locationKey: "GET https://example.com/api/users?id=1",
			want:        "https://example.com/api/users?id=1",
		},
		{
			name:        "host only",
			locationKey: "POST https://example.com",
			want:        "https://example.com",
		},
		{
			name:        "path without query",
			locationKey: "GET https://app.example.com/app/profile",
			want:        "https://app.example.com/app/profile",
		},
		{
			name:        "invalid location key",
			locationKey: "not-a-url",
			want:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EndpointURLFromLocationKey(tt.locationKey)
			if got != tt.want {
				t.Fatalf("EndpointURLFromLocationKey(%q) = %q, want %q", tt.locationKey, got, tt.want)
			}
		})
	}
}
