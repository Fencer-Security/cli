package cmd

import (
	"errors"
	"testing"
	"time"

	"fencer/cli/internal/auth"
)

func TestResolveBaseURLRejectsOriginMismatch(t *testing.T) {
	resetState(t)
	if err := auth.SaveTokens(&auth.TokenData{
		BaseURL:      "https://app.fencer.dev",
		ClientID:     "client",
		AccessToken:  "token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	baseURLFlag = "https://app.fencer-staging.dev"
	_, err := resolveBaseURL()
	if !errors.Is(err, auth.ErrOriginMismatch) {
		t.Fatalf("expected origin mismatch, got %v", err)
	}
}

func TestResolveBaseURLAllowsMatchingOrigin(t *testing.T) {
	resetState(t)
	if err := auth.SaveTokens(&auth.TokenData{
		BaseURL:      "https://app.fencer.dev",
		ClientID:     "client",
		AccessToken:  "token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	baseURLFlag = "https://app.fencer.dev/"
	got, err := resolveBaseURL()
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://app.fencer.dev" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveBaseURLRejectsInsecureOverride(t *testing.T) {
	resetState(t)
	baseURLFlag = "http://app.fencer.dev"
	_, err := resolveBaseURL()
	if !errors.Is(err, auth.ErrInsecureBaseURL) {
		t.Fatalf("expected insecure URL error, got %v", err)
	}
}

func TestLoginRejectsUnsafeBaseURL(t *testing.T) {
	resetState(t)
	rootCmd.SetArgs([]string{"login", "--base-url", "https://user:pass@app.fencer.dev"})
	err := rootCmd.Execute()
	if !errors.Is(err, auth.ErrInvalidBaseURL) {
		t.Fatalf("expected invalid base URL, got %v", err)
	}
}

func TestLoginRejectsProductionHTTP(t *testing.T) {
	resetState(t)
	rootCmd.SetArgs([]string{"login", "--base-url", "http://app.fencer.dev"})
	err := rootCmd.Execute()
	if !errors.Is(err, auth.ErrInsecureBaseURL) {
		t.Fatalf("expected insecure URL error, got %v", err)
	}
}
