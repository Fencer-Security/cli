package operations

import (
	"context"
	"fmt"
	"net/url"

	"fencer/cli/api"
	"fencer/cli/api/schema"
)

type Vulnerability struct {
	Slug              string `json:"slug"`
	Title             string `json:"title"`
	Severity          int    `json:"severity"`
	Status            string `json:"status"`
	PriorityLevel     string `json:"priority_level"`
	AssetName         string `json:"asset_name"`
	AssetResourceSlug string `json:"asset_resource_slug"`
	AssetResourceKind string `json:"asset_resource_kind"`
	AssigneeEmail     string `json:"assignee_email"`
	AssigneeName      string `json:"assignee_name"`
	WebURL            string `json:"web_url"`
}

func vulnerabilityFromAPI(v api.Vulnerability) Vulnerability {
	return Vulnerability{
		Slug:              v.Slug,
		Title:             v.Title,
		Severity:          v.Severity,
		Status:            v.Status,
		PriorityLevel:     v.PriorityLevel,
		AssetName:         v.AssetName,
		AssetResourceSlug: v.AssetResourceSlug,
		AssetResourceKind: v.AssetResourceKind,
		AssigneeEmail:     v.AssigneeEmail,
		AssigneeName:      v.AssigneeName,
		WebURL:            v.WebURL,
	}
}

type VulnerabilitiesListInput struct {
	OrganizationInput
	PageInput
	Asset         []string              `json:"asset,omitempty" jsonschema:"filter by asset slug(s) from the ASSET column, e.g. ARES-BDA"`
	Status        string                `json:"status,omitempty" jsonschema:"open | ready_for_verification | resolved | all (default: open)"`
	Category      VulnerabilityCategory `json:"category,omitempty"`
	Severity      []string              `json:"severity,omitempty" jsonschema:"severity filter(s): critical|high|medium|low|info or 0-4"`
	PriorityLevel []PriorityLevel       `json:"priority_level,omitempty"`
	Query         string                `json:"q,omitempty" jsonschema:"text search across title, description and slug"`
	Assignee      []string              `json:"assignee,omitempty" jsonschema:"filter by assignee email(s) or me"`
	HasAssignee   *bool                 `json:"has_assignee,omitempty" jsonschema:"true = only assigned, false = only unassigned"`
	Live          *bool                 `json:"live,omitempty" jsonschema:"only findings live on the default branch"`
	Ignored       *bool                 `json:"ignored,omitempty" jsonschema:"filter by ignored state"`
	Deferred      *bool                 `json:"deferred,omitempty" jsonschema:"filter by deferred state"`
	InScope       *bool                 `json:"in_scope,omitempty" jsonschema:"filter by in-scope state"`
	OrderBy       VulnerabilityOrderBy  `json:"order_by,omitempty"`
}

var VulnerabilitiesList = Register(Operation[VulnerabilitiesListInput, Page[Vulnerability]]{
	Name:        "vulnerabilities.list",
	Description: "List vulnerabilities (findings) for an organization, with optional filters. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input VulnerabilitiesListInput) (Page[Vulnerability], error) {
		org, err := input.require()
		if err != nil {
			return Page[Vulnerability]{}, err
		}
		filters, err := input.filters(client, org)
		if err != nil {
			return Page[Vulnerability]{}, err
		}
		opts, err := listOptions(input.PageInput, filters)
		if err != nil {
			return Page[Vulnerability]{}, err
		}
		result, err := client.GetVulnerabilities(org, opts)
		if err != nil {
			return Page[Vulnerability]{}, err
		}
		return pageFromAPI(result, vulnerabilityFromAPI), nil
	},
})

func (input VulnerabilitiesListInput) filters(client *api.Client, org string) (url.Values, error) {
	q := url.Values{}
	if err := addSeverityFilters(q, input.Severity); err != nil {
		return nil, err
	}
	addEach(q, "asset", input.Asset)
	if err := addAssigneeFilters(client, org, q, input.Assignee); err != nil {
		return nil, err
	}
	for _, level := range input.PriorityLevel {
		if err := ValidateEnum[schema.PriorityLevelEnum](string(level)); err != nil {
			return nil, err
		}
	}
	addEach(q, "priority_level", input.PriorityLevel)
	switch input.Status {
	case "":
		q.Set("status", "open")
	case "all":
	default:
		q.Set("status", input.Status)
	}
	if err := ValidateEnum[schema.VulnerabilitiesListParamsCategory](string(input.Category)); err != nil {
		return nil, err
	}
	setIf(q, "category", string(input.Category))
	setIf(q, "q", input.Query)
	setBoolPtr(q, "live", input.Live)
	setBoolPtr(q, "ignored_by", input.Ignored)
	setBoolPtr(q, "deferred", input.Deferred)
	setBoolPtr(q, "has_assignee", input.HasAssignee)
	setBoolPtr(q, "in_scope", input.InScope)
	if err := ValidateOrderBy[schema.VulnerabilitiesListParamsOrderBy](string(input.OrderBy)); err != nil {
		return nil, err
	}
	setIf(q, "order_by", string(input.OrderBy))
	return q, nil
}

type VulnerabilitiesGetInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"vulnerability slug, e.g. vuln-abc123"`
}

var VulnerabilitiesGet = Register(Operation[VulnerabilitiesGetInput, Vulnerability]{
	Name:        "vulnerabilities.get",
	Description: "Get a single vulnerability by its slug, including full detail. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input VulnerabilitiesGetInput) (Vulnerability, error) {
		org, err := input.require()
		if err != nil {
			return Vulnerability{}, err
		}
		if input.Slug == "" {
			return Vulnerability{}, fmt.Errorf("slug is required")
		}
		vuln, err := client.GetVulnerability(org, input.Slug)
		if err != nil {
			return Vulnerability{}, err
		}
		return vulnerabilityFromAPI(*vuln), nil
	},
})
