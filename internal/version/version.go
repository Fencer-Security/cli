package version

import (
	"runtime"
	"strings"
)

// Version is set at build time via -ldflags.
var Version = "0.0.0"

// Commit is the git commit the binary was built from, set via -ldflags.
var Commit = "unknown"

// Date is the build timestamp, set via -ldflags.
var Date = "unknown"

// IsPlaceholder reports whether Version is the compile-default 0.0.0 used for local
// development builds. Release and production distribution builds must not use it.
func IsPlaceholder() bool {
	v := strings.TrimPrefix(strings.TrimSpace(Version), "v")
	return v == "" || v == "0.0.0"
}

// ClientHeader returns the value for the X-Fencer-Client header.
func ClientHeader() string {
	return "fencer-cli/" + Version
}

// Info is the structured build identity printed by `fencer version`.
type Info struct {
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	Date           string `json:"date"`
	GoOS           string `json:"goos"`
	GoArch         string `json:"goarch"`
	DefaultBaseURL string `json:"default_base_url"`
}

// Current returns the build identity, including the compiled-in API default.
func Current(defaultBaseURL string) Info {
	return Info{
		Version:        Version,
		Commit:         Commit,
		Date:           Date,
		GoOS:           runtime.GOOS,
		GoArch:         runtime.GOARCH,
		DefaultBaseURL: defaultBaseURL,
	}
}
