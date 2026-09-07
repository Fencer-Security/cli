package version

import "testing"

func TestIsPlaceholder(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "0.0.0"
	if !IsPlaceholder() {
		t.Fatal("expected 0.0.0 to be a placeholder")
	}

	Version = "v0.0.0"
	if !IsPlaceholder() {
		t.Fatal("expected v0.0.0 to be a placeholder")
	}

	Version = ""
	if !IsPlaceholder() {
		t.Fatal("expected empty version to be a placeholder")
	}

	Version = "1.2.3"
	if IsPlaceholder() {
		t.Fatal("expected 1.2.3 not to be a placeholder")
	}

	Version = "0.0.0-ci"
	if IsPlaceholder() {
		t.Fatal("expected 0.0.0-ci not to be a placeholder")
	}
}

func TestClientHeader(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "1.4.0"
	if got := ClientHeader(); got != "fencer-cli/1.4.0" {
		t.Fatalf("got %q", got)
	}
}

func TestCurrent(t *testing.T) {
	origV, origC, origD := Version, Commit, Date
	t.Cleanup(func() {
		Version = origV
		Commit = origC
		Date = origD
	})

	Version = "1.2.3"
	Commit = "abc123"
	Date = "2026-08-31T00:00:00Z"

	info := Current("https://app.fencer.dev")
	if info.Version != "1.2.3" {
		t.Fatalf("version: got %q", info.Version)
	}
	if info.Commit != "abc123" {
		t.Fatalf("commit: got %q", info.Commit)
	}
	if info.Date != "2026-08-31T00:00:00Z" {
		t.Fatalf("date: got %q", info.Date)
	}
	if info.DefaultBaseURL != "https://app.fencer.dev" {
		t.Fatalf("default_base_url: got %q", info.DefaultBaseURL)
	}
	if info.GoOS == "" || info.GoArch == "" {
		t.Fatal("expected goos and goarch")
	}
}
