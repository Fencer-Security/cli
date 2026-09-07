package auth

import (
	"encoding/json"
	"os"
	"path/filepath"

	"fencer/cli/internal/config"
)

// UserCache is the on-disk cache of email→user_id per org, plus the current user's email.
type UserCache struct {
	Orgs map[string]*OrgCache `json:"orgs"`
}

// OrgCache caches email→user_id for a single organization and remembers the current user's email.
type OrgCache struct {
	CurrentEmail string         `json:"current_email,omitempty"`
	Emails       map[string]int `json:"emails"`
}

// LoadUserCache reads the cache file, returning an empty cache if it doesn't exist.
func LoadUserCache() (*UserCache, error) {
	path, err := config.UserCacheFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &UserCache{Orgs: map[string]*OrgCache{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var cache UserCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	if cache.Orgs == nil {
		cache.Orgs = map[string]*OrgCache{}
	}
	return &cache, nil
}

// Save writes the cache to disk.
func (c *UserCache) Save() error {
	path, err := config.UserCacheFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Org returns (and lazily creates) the entry for an org.
func (c *UserCache) Org(slug string) *OrgCache {
	if c.Orgs == nil {
		c.Orgs = map[string]*OrgCache{}
	}
	if c.Orgs[slug] == nil {
		c.Orgs[slug] = &OrgCache{Emails: map[string]int{}}
	} else if c.Orgs[slug].Emails == nil {
		c.Orgs[slug].Emails = map[string]int{}
	}
	return c.Orgs[slug]
}
