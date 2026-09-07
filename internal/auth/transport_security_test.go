package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBearerTransportOmitsAuthorizationOnOriginMismatch(t *testing.T) {
	var gotAuth string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(foreign.Close)

	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(home.Close)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := SaveTokens(&TokenData{
		BaseURL:      home.URL,
		ClientID:     "client",
		AccessToken:  "secret-token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := NewAuthenticatedClient(home.URL).Get(foreign.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if gotAuth != "" {
		t.Fatalf("authorization leaked to foreign origin: %q", gotAuth)
	}
}

func TestBearerTransportOmitsFencerTokenOnOriginMismatch(t *testing.T) {
	var gotAuth string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(foreign.Close)

	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(home.Close)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("FENCER_TOKEN", "fcr_ci-token")

	resp, err := NewAuthenticatedClient(home.URL).Get(foreign.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if gotAuth != "" {
		t.Fatalf("FENCER_TOKEN leaked to foreign origin: %q", gotAuth)
	}
}

func TestBearerTransportStripsAuthorizationOnCrossOriginRedirect(t *testing.T) {
	var destAuth string
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(dest.Close)

	var srcAuth string
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srcAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, dest.URL+"/landed", http.StatusFound)
	}))
	t.Cleanup(src.Close)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := SaveTokens(&TokenData{
		BaseURL:      src.URL,
		ClientID:     "client",
		AccessToken:  "secret-token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := NewAuthenticatedClient(src.URL).Get(src.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if srcAuth != "Bearer secret-token" {
		t.Fatalf("source origin Authorization = %q", srcAuth)
	}
	if destAuth != "" {
		t.Fatalf("authorization leaked across redirect: %q", destAuth)
	}
}

func TestConcurrentRefreshDoesNotCorruptTokens(t *testing.T) {
	var refreshCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token/" {
			refreshCount.Add(1)
			time.Sleep(50 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"refreshed","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := SaveTokens(&TokenData{
		BaseURL:      srv.URL,
		ClientID:     "client",
		AccessToken:  "expired",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	client := NewAuthenticatedClient(srv.URL)
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(srv.URL + "/api")
			if err != nil {
				errCh <- err
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	if refreshCount.Load() != 1 {
		t.Fatalf("expected a single refresh, got %d", refreshCount.Load())
	}
	tokens, err := LoadTokens()
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "refreshed" {
		t.Fatalf("access = %q", tokens.AccessToken)
	}
	if tokens.RefreshToken != "refresh" {
		t.Fatalf("refresh token not preserved: %q", tokens.RefreshToken)
	}
}
