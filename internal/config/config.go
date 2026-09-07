package config

import (
	"os"
	"path/filepath"
)

// DefaultBaseURL is used when no --base-url flag is passed and no base URL is
// stored yet (i.e. before the first login). Set at build time via -ldflags for
// prod builds (see cli/Makefile's build-prod target); defaults to local dev
// otherwise.
var DefaultBaseURL = "http://app.fencer.home"

// Dir returns the XDG config directory for fencer (~/.config/fencer/).
func Dir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "fencer"), nil
}

// TokenFilePath returns the path to the token store file.
func TokenFilePath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tokens.json"), nil
}

// UserCacheFilePath returns the path to the per-org email→id cache file.
func UserCacheFilePath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "users.json"), nil
}
