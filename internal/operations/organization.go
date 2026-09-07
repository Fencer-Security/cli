package operations

import "fmt"

// OrganizationInput is the shared organization selector for org-scoped operations.
type OrganizationInput struct {
	OrganizationSlug string `json:"organization_slug,omitempty" jsonschema:"organization slug; defaults to --org / FENCER_ORG"`
}

func (in OrganizationInput) require() (string, error) {
	if in.OrganizationSlug == "" {
		return "", fmt.Errorf("organization slug is required — use --org <slug> or set FENCER_ORG")
	}
	return in.OrganizationSlug, nil
}
