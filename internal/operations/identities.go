package operations

import (
	"context"
	"net/url"

	"fencer/cli/api"
	"fencer/cli/api/schema"
)

type Identity struct {
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	IdentityType string `json:"identity_type"`
}

func identityFromAPI(id api.Identity) Identity {
	return Identity{
		Slug:         id.Slug,
		Name:         id.Name,
		Email:        id.Email,
		IdentityType: id.IdentityType,
	}
}

type IdentitiesListInput struct {
	OrganizationInput
	PageInput
	Type         string          `json:"identity_type,omitempty" jsonschema:"filter by identity_type"`
	Status       string          `json:"identity_status,omitempty" jsonschema:"filter by identity_status"`
	Relationship string          `json:"identity_relationship,omitempty" jsonschema:"filter by identity_relationship"`
	NeedsReview  *bool           `json:"needs_review,omitempty" jsonschema:"true = needing review, false = reviewed"`
	HasOwner     *bool           `json:"has_owner,omitempty" jsonschema:"true = with an owner, false = orphaned"`
	Query        string          `json:"q,omitempty" jsonschema:"text search across display name, email, vendor username"`
	OrderBy      IdentityOrderBy `json:"order_by,omitempty"`
}

var IdentitiesList = Register(Operation[IdentitiesListInput, Page[Identity]]{
	Name:        "identities.list",
	Description: "List identities for an organization, with optional filters. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input IdentitiesListInput) (Page[Identity], error) {
		org, err := input.require()
		if err != nil {
			return Page[Identity]{}, err
		}
		filters, err := input.filters()
		if err != nil {
			return Page[Identity]{}, err
		}
		opts, err := listOptions(input.PageInput, filters)
		if err != nil {
			return Page[Identity]{}, err
		}
		result, err := client.GetIdentities(org, opts)
		if err != nil {
			return Page[Identity]{}, err
		}
		return pageFromAPI(result, identityFromAPI), nil
	},
})

func (input IdentitiesListInput) filters() (url.Values, error) {
	q := url.Values{}
	setIf(q, "identity_type", input.Type)
	setIf(q, "identity_status", input.Status)
	setIf(q, "identity_relationship", input.Relationship)
	setBoolPtr(q, "needs_review", input.NeedsReview)
	setBoolPtr(q, "has_owner", input.HasOwner)
	setIf(q, "q", input.Query)
	if err := ValidateOrderBy[schema.IdentitiesListParamsOrderBy](string(input.OrderBy)); err != nil {
		return nil, err
	}
	setIf(q, "order_by", string(input.OrderBy))
	return q, nil
}
