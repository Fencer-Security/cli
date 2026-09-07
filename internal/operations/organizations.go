package operations

import (
	"context"

	"fencer/cli/api"
)

// Organization is the public organization shape returned by Fencer operations.
type Organization struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// OrganizationsListInput contains pagination for organizations.list.
type OrganizationsListInput struct {
	PageInput
}

// OrganizationsList is the canonical operation for discovering accessible organizations.
var OrganizationsList = Register(Operation[OrganizationsListInput, Page[Organization]]{
	Name:        "organizations.list",
	Description: "List organizations accessible to the authenticated user. Call this first to discover organization slugs.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input OrganizationsListInput) (Page[Organization], error) {
		opts, err := listOptions(input.PageInput, nil)
		if err != nil {
			return Page[Organization]{}, err
		}
		result, err := client.GetOrganizations(opts)
		if err != nil {
			return Page[Organization]{}, err
		}
		return pageFromAPI(result, func(org api.Organization) Organization {
			return Organization{Name: org.Name, Slug: org.Slug}
		}), nil
	},
})
