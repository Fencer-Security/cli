package operations

import (
	"fmt"
	"strconv"
	"strings"

	"fencer/cli/api"
	"fencer/cli/internal/auth"
)

// ResolveUserID returns a user_id for assignment. Exactly one of email or me must be set.
func ResolveUserID(client *api.Client, orgSlug, email string, me bool) (int, string, error) {
	if (email == "") == !me {
		return 0, "", fmt.Errorf("exactly one of email or me is required")
	}

	cache, err := auth.LoadUserCache()
	if err != nil {
		return 0, "", fmt.Errorf("failed to load user cache: %w", err)
	}
	org := cache.Org(orgSlug)

	if me {
		if org.CurrentEmail != "" {
			if id, ok := org.Emails[org.CurrentEmail]; ok {
				return id, org.CurrentEmail, nil
			}
		}
		current, err := client.GetCurrentUser(orgSlug)
		if err != nil {
			return 0, "", fmt.Errorf("failed to resolve current user: %w", err)
		}
		org.CurrentEmail = current.Email
		org.Emails[current.Email] = current.ID
		if err := cache.Save(); err != nil {
			return 0, "", fmt.Errorf("failed to save user cache: %w", err)
		}
		return current.ID, current.Email, nil
	}

	email = strings.ToLower(strings.TrimSpace(email))
	if id, ok := org.Emails[email]; ok {
		return id, email, nil
	}

	page, err := client.ListOrgUsers(orgSlug, email, api.ListOptions{PageSize: 10})
	if err != nil {
		return 0, "", fmt.Errorf("failed to look up user by email: %w", err)
	}

	var matches []api.OrgUser
	for _, u := range page.Results {
		if strings.EqualFold(u.Email, email) {
			matches = append(matches, u)
		}
	}
	switch len(matches) {
	case 0:
		return 0, "", fmt.Errorf("no org member found with email %q", email)
	case 1:
		org.Emails[email] = matches[0].ID
		if err := cache.Save(); err != nil {
			return 0, "", fmt.Errorf("failed to save user cache: %w", err)
		}
		return matches[0].ID, email, nil
	default:
		return 0, "", fmt.Errorf("multiple org members matched %q — be more specific", email)
	}
}

// ResolveAssigneeFilter accepts "me" or an email and returns the matching numeric user ID.
func ResolveAssigneeFilter(client *api.Client, orgSlug, value string) (string, error) {
	if value == "me" {
		id, _, err := ResolveUserID(client, orgSlug, "", true)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(id), nil
	}
	if !strings.Contains(value, "@") {
		return "", fmt.Errorf("invalid assignee %q (expected email or \"me\")", value)
	}
	id, _, err := ResolveUserID(client, orgSlug, value, false)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(id), nil
}
