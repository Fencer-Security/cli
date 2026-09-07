package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var (
	// ErrInvalidBaseURL is returned when a base URL cannot be used as an API origin.
	ErrInvalidBaseURL = errors.New("invalid API base URL")
	// ErrInsecureBaseURL is returned when HTTP is used for a non-local origin.
	ErrInsecureBaseURL = errors.New("API base URL must use HTTPS")
	// ErrOriginMismatch is returned when --base-url does not match the stored origin.
	ErrOriginMismatch = errors.New("stored credentials are bound to a different API origin")
)

func isLocalDevHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "app.fencer.home":
		return true
	default:
		return false
	}
}

// NormalizeBaseURL parses and canonicalizes an API base URL.
// HTTP is allowed only for explicitly supported local-development hosts.
func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: URL is empty", ErrInvalidBaseURL)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidBaseURL, err)
	}
	if u.Opaque != "" {
		return "", fmt.Errorf("%w: opaque URLs are not allowed", ErrInvalidBaseURL)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https":
		u.Scheme = scheme
	case "":
		return "", fmt.Errorf("%w: scheme is missing", ErrInvalidBaseURL)
	default:
		return "", fmt.Errorf("%w: scheme %q is not allowed", ErrInvalidBaseURL, u.Scheme)
	}

	if u.User != nil {
		return "", fmt.Errorf("%w: embedded credentials are not allowed", ErrInvalidBaseURL)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%w: host is missing", ErrInvalidBaseURL)
	}

	if scheme == "http" && !isLocalDevHost(host) {
		return "", fmt.Errorf("%w: HTTP is only allowed for local development hosts", ErrInsecureBaseURL)
	}

	if u.RawQuery != "" {
		return "", fmt.Errorf("%w: query parameters are not allowed", ErrInvalidBaseURL)
	}

	u.Fragment = ""
	u.RawQuery = ""
	u.Path = strings.TrimRight(u.Path, "/")

	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if port != "" {
		u.Host += ":" + port
	}

	return strings.TrimRight(u.String(), "/"), nil
}

// SameOrigin reports whether two URLs share scheme, host, and effective port.
func SameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return sameOriginURLs(ua, ub)
}

func sameOriginURLs(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return originKey(a) == originKey(b)
}

func originKey(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + host + ":" + port
}

// OriginMismatchError explains that stored credentials cannot be sent elsewhere.
func OriginMismatchError(stored, requested string) error {
	return fmt.Errorf("%w: credentials are bound to %s, not %s; run 'fencer login --base-url %s' to reauthenticate",
		ErrOriginMismatch, stored, requested, requested)
}

func requestURLString(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	u := *req.URL
	if u.Scheme == "" || u.Host == "" {
		if req.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
		u.Host = req.Host
	}
	return u.String()
}
