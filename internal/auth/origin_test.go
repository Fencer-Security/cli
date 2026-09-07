package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{name: "https production", raw: "https://app.fencer.dev", want: "https://app.fencer.dev"},
		{name: "trailing slash", raw: "https://app.fencer.dev/", want: "https://app.fencer.dev"},
		{name: "default https port", raw: "https://app.fencer.dev:443", want: "https://app.fencer.dev"},
		{name: "uppercase host", raw: "https://App.Fencer.DEV", want: "https://app.fencer.dev"},
		{name: "local http home", raw: "http://app.fencer.home", want: "http://app.fencer.home"},
		{name: "localhost http", raw: "http://localhost:8000", want: "http://localhost:8000"},
		{name: "loopback http", raw: "http://127.0.0.1:12345", want: "http://127.0.0.1:12345"},
		{name: "ipv6 loopback http", raw: "http://[::1]:8080", want: "http://[::1]:8080"},
		{name: "empty", raw: "  ", wantErr: ErrInvalidBaseURL},
		{name: "missing scheme", raw: "app.fencer.dev", wantErr: ErrInvalidBaseURL},
		{name: "ftp scheme", raw: "ftp://app.fencer.dev", wantErr: ErrInvalidBaseURL},
		{name: "file scheme", raw: "file:///etc/passwd", wantErr: ErrInvalidBaseURL},
		{name: "javascript scheme", raw: "javascript:alert(1)", wantErr: ErrInvalidBaseURL},
		{name: "embedded userinfo", raw: "https://user:pass@app.fencer.dev", wantErr: ErrInvalidBaseURL},
		{name: "embedded user", raw: "https://user@app.fencer.dev", wantErr: ErrInvalidBaseURL},
		{name: "query string", raw: "https://app.fencer.dev?x=1", wantErr: ErrInvalidBaseURL},
		{name: "production http", raw: "http://app.fencer.dev", wantErr: ErrInsecureBaseURL},
		{name: "staging http", raw: "http://app.fencer-staging.dev", wantErr: ErrInsecureBaseURL},
		{name: "localhost lookalike http", raw: "http://localhost.evil.example", wantErr: ErrInsecureBaseURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeBaseURL(tt.raw)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NormalizeBaseURL(%q) error = %v, want %v", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeBaseURL(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeBaseURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestSameOrigin(t *testing.T) {
	if !SameOrigin("https://app.fencer.dev", "https://app.fencer.dev/api/v1/org/x/") {
		t.Fatal("expected path to be ignored for origin comparison")
	}
	if !SameOrigin("https://app.fencer.dev", "https://app.fencer.dev:443") {
		t.Fatal("expected default https port to match")
	}
	if SameOrigin("https://app.fencer.dev", "https://app.fencer-staging.dev") {
		t.Fatal("expected different hosts not to match")
	}
	if SameOrigin("https://app.fencer.dev", "http://app.fencer.dev") {
		t.Fatal("expected different schemes not to match")
	}
	if SameOrigin("http://127.0.0.1:1", "http://127.0.0.1:2") {
		t.Fatal("expected different ports not to match")
	}
}

func TestOriginMismatchError(t *testing.T) {
	err := OriginMismatchError("https://app.fencer.dev", "https://app.fencer-staging.dev")
	if !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("expected ErrOriginMismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "fencer login --base-url") {
		t.Fatalf("expected reauth guidance, got %v", err)
	}
}
