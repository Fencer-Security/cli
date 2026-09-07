package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"fencer/cli/internal/config"
	"fencer/cli/internal/version"
)

func TestVersionCommandTable(t *testing.T) {
	resetState(t)
	origV, origC, origD, origURL := version.Version, version.Commit, version.Date, config.DefaultBaseURL
	t.Cleanup(func() {
		version.Version = origV
		version.Commit = origC
		version.Date = origD
		config.DefaultBaseURL = origURL
	})
	version.Version = "1.2.3"
	version.Commit = "deadbeef"
	version.Date = "2026-08-31T12:00:00Z"
	config.DefaultBaseURL = "https://app.fencer.dev"

	rootCmd.SetArgs([]string{"version"})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("version: %v", err)
		}
	})
	for _, want := range []string{
		"fencer 1.2.3",
		"commit  deadbeef",
		"built   2026-08-31T12:00:00Z",
		"api     https://app.fencer.dev",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestVersionCommandJSON(t *testing.T) {
	resetState(t)
	origV, origURL := version.Version, config.DefaultBaseURL
	t.Cleanup(func() {
		version.Version = origV
		config.DefaultBaseURL = origURL
	})
	version.Version = "9.9.9"
	config.DefaultBaseURL = "https://app.fencer.dev"

	rootCmd.SetArgs([]string{"version", "--output", "json"})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("version: %v", err)
		}
	})
	var info version.Info
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if info.Version != "9.9.9" {
		t.Fatalf("version: got %q", info.Version)
	}
	if info.DefaultBaseURL != "https://app.fencer.dev" {
		t.Fatalf("default_base_url: got %q", info.DefaultBaseURL)
	}
}

func TestVersionFlag(t *testing.T) {
	resetState(t)
	orig := version.Version
	t.Cleanup(func() {
		version.Version = orig
		rootCmd.Version = orig
	})
	version.Version = "2.0.0"
	rootCmd.Version = version.Version

	rootCmd.SetArgs([]string{"--version"})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("--version: %v", err)
		}
	})
	if strings.TrimSpace(out) != "2.0.0" {
		t.Fatalf("got %q", out)
	}
}
