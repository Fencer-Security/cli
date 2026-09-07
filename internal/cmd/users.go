package cmd

import (
	"fmt"

	"fencer/cli/api"
	"fencer/cli/internal/operations"
)

func resolveUserID(client *api.Client, orgSlug, emailFlag string, meFlag bool) (int, string, error) {
	id, email, err := operations.ResolveUserID(client, orgSlug, emailFlag, meFlag)
	if err != nil && err.Error() == "exactly one of email or me is required" {
		return 0, "", fmt.Errorf("exactly one of --email or --me is required")
	}
	return id, email, err
}
