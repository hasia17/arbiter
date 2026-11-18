package main

import (
	"path/filepath"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://example.com", true},
		{"http://example.com/path?q=1", true},
		{"HTTPS://example.com", true},
		{"https://", false},
		{"ftp://example.com", false},
		{"example.com", false},
		{"://broken", false},
	}
	for _, tt := range tests {
		err := validateURL(tt.url)
		if (err == nil) != tt.ok {
			t.Errorf("validateURL(%q) = %v, want ok=%v", tt.url, err, tt.ok)
		}
	}
}

func TestReportPath(t *testing.T) {
	got, err := reportPath("example.pdf")
	if err != nil || got != filepath.Join("reports", "example.pdf") {
		t.Errorf("reportPath(example.pdf) = %q, %v", got, err)
	}

	for _, bad := range []string{"../escape.pdf", "sub/dir.pdf", "..", "."} {
		if _, err := reportPath(bad); err == nil {
			t.Errorf("reportPath(%q) should fail", bad)
		}
	}
}
