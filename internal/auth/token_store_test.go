package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSaveTokensAtomicAndConcurrent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	const n = 20
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- SaveTokens(&TokenData{
				BaseURL:      "https://app.fencer.dev",
				ClientID:     "client",
				AccessToken:  "access",
				RefreshToken: "refresh",
				ExpiresAt:    time.Now().Add(time.Hour),
			})
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	tokens, err := LoadTokens()
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.BaseURL != "https://app.fencer.dev" {
		t.Fatalf("corrupt or incomplete token file: %+v", tokens)
	}

	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "fencer", "tokens.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("tokens.json mode = %o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed TokenData
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("token file is not valid JSON: %v\n%s", err, data)
	}
}

func TestDeleteTokensRemovesFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := SaveTokens(&TokenData{BaseURL: "https://app.fencer.dev", AccessToken: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteTokens(); err != nil {
		t.Fatal(err)
	}
	_, err := LoadTokens()
	if !os.IsNotExist(err) {
		t.Fatalf("expected not exist after delete, got %v", err)
	}
}

func TestIsExpired(t *testing.T) {
	cases := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"zero means no client-side expiry", time.Time{}, false},
		{"past", time.Now().Add(-time.Minute), true},
		{"inside the 30s buffer", time.Now().Add(10 * time.Second), true},
		{"future", time.Now().Add(time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := (&TokenData{ExpiresAt: tc.expiresAt}).IsExpired()
			if got != tc.want {
				t.Fatalf("IsExpired() = %v, want %v", got, tc.want)
			}
		})
	}
}
