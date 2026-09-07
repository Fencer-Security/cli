package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fencer/cli/internal/version"
)

func TestBearerTransportSetsClientHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Fencer-Client")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	tokensPath := filepath.Join(tmpDir, "fencer", "tokens.json")
	if err := os.MkdirAll(filepath.Dir(tokensPath), 0o700); err != nil {
		t.Fatal(err)
	}
	tokens := TokenData{
		AccessToken:  "test-token",
		RefreshToken: "test-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		BaseURL:      srv.URL,
		ClientID:     "test-client",
	}
	data, _ := json.Marshal(tokens)
	if err := os.WriteFile(tokensPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewAuthenticatedClient(srv.URL)
	resp, err := client.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	expected := "fencer-cli/" + version.Version
	if gotHeader != expected {
		t.Errorf("expected X-Fencer-Client=%q, got %q", expected, gotHeader)
	}
}

func TestNewAuthenticatedClientTimeout(t *testing.T) {
	if got := NewAuthenticatedClient("https://app.example.test").Timeout; got != defaultHTTPTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultHTTPTimeout, got)
	}

	t.Setenv("FENCER_HTTP_TIMEOUT", "2s")
	if got := NewAuthenticatedClient("https://app.example.test").Timeout; got != 2*time.Second {
		t.Errorf("expected FENCER_HTTP_TIMEOUT override 2s, got %v", got)
	}

	t.Setenv("FENCER_HTTP_TIMEOUT", "garbage")
	if got := NewAuthenticatedClient("https://app.example.test").Timeout; got != defaultHTTPTimeout {
		t.Errorf("expected fallback to default on invalid override, got %v", got)
	}
}

func TestAuthenticatedClientAbortsSlowRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	tokensPath := filepath.Join(tmpDir, "fencer", "tokens.json")
	if err := os.MkdirAll(filepath.Dir(tokensPath), 0o700); err != nil {
		t.Fatal(err)
	}
	tokens := TokenData{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(time.Hour),
		BaseURL:     srv.URL,
		ClientID:    "test-client",
	}
	data, _ := json.Marshal(tokens)
	if err := os.WriteFile(tokensPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FENCER_HTTP_TIMEOUT", "20ms")
	client := NewAuthenticatedClient(srv.URL)
	resp, err := client.Get(srv.URL + "/slow")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected timeout error for slow request, got nil")
	}
}

func TestBearerTransportUsesFencerTokenEnv(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("FENCER_TOKEN", "fcr_ci-token")

	client := NewAuthenticatedClient(srv.URL)
	resp, err := client.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if gotAuth != "Bearer fcr_ci-token" {
		t.Errorf("expected FENCER_TOKEN bearer header, got %q", gotAuth)
	}
}

func TestBearerTransportBindsFencerTokenToConfiguredOriginWithoutStoredCredentials(t *testing.T) {
	var gotAuth string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer foreign.Close()

	// The CI shape: FENCER_TOKEN exported, `fencer login` never run, so no tokens.json exists.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("FENCER_TOKEN", "fcr_ci-token")

	client := NewAuthenticatedClient("https://home.example.test")
	resp, err := client.Get(foreign.URL + "/api")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if gotAuth != "" {
		t.Fatalf("FENCER_TOKEN leaked to an origin other than the configured base URL: %q", gotAuth)
	}
}

func TestBearerTransportNeverSendsFencerTokenWithoutABoundOrigin(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("FENCER_TOKEN", "fcr_ci-token")

	client := &http.Client{Transport: &BearerTransport{}}
	resp, err := client.Get(srv.URL + "/api")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if gotAuth != "" {
		t.Fatalf("FENCER_TOKEN sent by a transport with no bound origin: %q", gotAuth)
	}
}

func TestBearerTransportSendsStoredServiceAccountTokenWithoutRefresh(t *testing.T) {
	var gotAuth string
	var refreshCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token/" {
			refreshCalls++
		}
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	tokensPath := filepath.Join(tmpDir, "fencer", "tokens.json")
	if err := os.MkdirAll(filepath.Dir(tokensPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// Exactly what `fencer login --token` writes: no refresh token, no expiry.
	tokens := TokenData{
		AccessToken: "fcr_stored",
		BaseURL:     srv.URL,
	}
	data, _ := json.Marshal(tokens)
	if err := os.WriteFile(tokensPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewAuthenticatedClient(srv.URL)
	resp, err := client.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if gotAuth != "Bearer fcr_stored" {
		t.Errorf("expected stored service-account token, got %q", gotAuth)
	}
	if refreshCalls != 0 {
		t.Errorf("expected no refresh attempt, got %d", refreshCalls)
	}
}
