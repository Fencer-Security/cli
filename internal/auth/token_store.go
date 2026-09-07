package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fencer/cli/internal/config"
)

// TokenData holds the persisted OAuth token information.
type TokenData struct {
	BaseURL      string    `json:"base_url"`
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// IsExpired reports whether the access token has expired (with a 30-second buffer).
// A zero ExpiresAt means the client knows no expiry - service-account tokens are
// enforced by the server, which may also issue them without one - and is never
// treated as expired here.
func (t *TokenData) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(30 * time.Second).After(t.ExpiresAt)
}

func tokenLockPath() (string, error) {
	path, err := config.TokenFilePath()
	if err != nil {
		return "", err
	}
	return path + ".lock", nil
}

func withTokenLock(fn func() error) error {
	lockPath, err := tokenLockPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := lockFile(f); err != nil {
		return fmt.Errorf("failed to lock token store: %w", err)
	}
	defer func() { _ = unlockFile(f) }()
	return fn()
}

// LoadTokens reads the token file from disk.
func LoadTokens() (*TokenData, error) {
	path, err := config.TokenFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var tokens TokenData
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

// SaveTokens writes token data to disk atomically, creating the config directory if needed.
func SaveTokens(tokens *TokenData) error {
	return withTokenLock(func() error {
		return saveTokensUnlocked(tokens)
	})
}

func saveTokensUnlocked(tokens *TokenData) error {
	path, err := config.TokenFilePath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "tokens-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return err
		}
		if err := os.Rename(tmpName, path); err != nil {
			return err
		}
	}
	committed = true
	return nil
}

// DeleteTokens removes the token file from disk.
func DeleteTokens() error {
	return withTokenLock(func() error {
		path, err := config.TokenFilePath()
		if err != nil {
			return err
		}
		err = os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	})
}
