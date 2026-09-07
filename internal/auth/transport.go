package auth

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"fencer/cli/internal/version"
)

// defaultHTTPTimeout bounds a single API exchange (connect + response + body read). It sits just
// under the pentest wrapper's 60s subprocess kill so a slow request fails with a clean
// "context deadline exceeded" the caller can surface, instead of the process being SIGKILLed.
const defaultHTTPTimeout = 55 * time.Second

const maxRedirects = 10

// httpTimeout returns the request timeout, overridable via FENCER_HTTP_TIMEOUT (a Go duration).
func httpTimeout() time.Duration {
	if v := os.Getenv("FENCER_HTTP_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultHTTPTimeout
}

// BearerTransport is an http.RoundTripper that injects an Authorization header
// and auto-refreshes the token when it is expired. The header is only attached
// when the request origin matches the origin the credentials are bound to:
// BoundOrigin (the CLI's configured API base URL) for a FENCER_TOKEN, the
// origin stored alongside the credentials for an OAuth login.
type BearerTransport struct {
	Base http.RoundTripper
	// BoundOrigin is the normalized API base URL this client was built for. An
	// empty value fails closed: FENCER_TOKEN is never sent anywhere.
	BoundOrigin string
}

func (t *BearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("X-Fencer-Client", version.ClientHeader())

	if token := strings.TrimSpace(os.Getenv("FENCER_TOKEN")); token != "" {
		if t.BoundOrigin == "" || !SameOrigin(t.BoundOrigin, requestURLString(req)) {
			return t.roundTrip(clone)
		}
		clone.Header.Set("Authorization", "Bearer "+token)
		return t.roundTrip(clone)
	}

	tokens, err := LoadTokens()
	if err != nil {
		return nil, fmt.Errorf("not logged in — run 'fencer login' first: %w", err)
	}

	if !SameOrigin(tokens.BaseURL, requestURLString(req)) {
		return t.roundTrip(clone)
	}

	if tokens.IsExpired() {
		err := withTokenLock(func() error {
			latest, err := LoadTokens()
			if err != nil {
				return err
			}
			if !latest.IsExpired() {
				tokens = latest
				return nil
			}
			refreshed, err := Refresh(latest.BaseURL, latest.ClientID, latest.RefreshToken)
			if err != nil {
				return err
			}
			refreshed.BaseURL = latest.BaseURL
			refreshed.ClientID = latest.ClientID
			if err := saveTokensUnlocked(refreshed); err != nil {
				return fmt.Errorf("failed to save refreshed tokens: %w", err)
			}
			tokens = refreshed
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("token refresh failed — run 'fencer login' again: %w", err)
		}
	}

	clone.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	return t.roundTrip(clone)
}

func (t *BearerTransport) roundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func boundRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) > 0 && !sameOriginURLs(via[len(via)-1].URL, req.URL) {
		req.Header.Del("Authorization")
	}
	return nil
}

// NewAuthenticatedClient returns an *http.Client that injects Bearer tokens for
// requests to baseURL's origin.
func NewAuthenticatedClient(baseURL string) *http.Client {
	return &http.Client{
		Transport:     &BearerTransport{BoundOrigin: baseURL},
		Timeout:       httpTimeout(),
		CheckRedirect: boundRedirect,
	}
}
