package main

import "testing"

func TestValidateDiscoverTargetURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "public host", raw: "https://example.com/login", wantErr: false},
		{name: "localhost blocked", raw: "http://localhost:8080", wantErr: true},
		{name: "private ip blocked", raw: "http://10.0.0.2", wantErr: true},
		{name: "loopback blocked", raw: "http://127.0.0.1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiscoverTargetURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDiscoverTargetURL(%q) error=%v wantErr=%v", tt.raw, err, tt.wantErr)
			}
		})
	}
}
