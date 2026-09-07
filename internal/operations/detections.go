package operations

import (
	"context"
	"fmt"
	"net/url"

	"fencer/cli/api"
	"fencer/cli/api/schema"
)

type Detection struct {
	Slug          string `json:"slug"`
	Title         string `json:"title"`
	Severity      int    `json:"severity"`
	Status        string `json:"status"`
	AssigneeEmail string `json:"assignee_email"`
	AssigneeName  string `json:"assignee_name"`
}

func detectionFromAPI(d api.Detection) Detection {
	return Detection{
		Slug:          d.Slug,
		Title:         d.Title,
		Severity:      d.Severity,
		Status:        d.Status,
		AssigneeEmail: d.AssigneeEmail,
		AssigneeName:  d.AssigneeName,
	}
}

type DetectionsListInput struct {
	OrganizationInput
	PageInput
	Asset       []string         `json:"asset,omitempty" jsonschema:"filter by asset slug(s)"`
	Status      string           `json:"status,omitempty" jsonschema:"filter by detection status"`
	Severity    []string         `json:"severity,omitempty" jsonschema:"severity filter(s): critical|high|medium|low|info or 0-4"`
	Assignee    []string         `json:"assignee,omitempty" jsonschema:"filter by assignee email(s) or me"`
	HasAssignee *bool            `json:"has_assignee,omitempty" jsonschema:"true = assigned, false = unassigned"`
	Query       string           `json:"q,omitempty" jsonschema:"text search across slug, title, description, asset name"`
	DetectedAt  string           `json:"detected_at,omitempty" jsonschema:"relative time window: 24h|7d|30d|90d|365d"`
	OrderBy     DetectionOrderBy `json:"order_by,omitempty"`
}

var DetectionsList = Register(Operation[DetectionsListInput, Page[Detection]]{
	Name:        "detections.list",
	Description: "List SIEM detections for an organization, with optional filters. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input DetectionsListInput) (Page[Detection], error) {
		org, err := input.require()
		if err != nil {
			return Page[Detection]{}, err
		}
		filters, err := input.filters(client, org)
		if err != nil {
			return Page[Detection]{}, err
		}
		opts, err := listOptions(input.PageInput, filters)
		if err != nil {
			return Page[Detection]{}, err
		}
		result, err := client.GetDetections(org, opts)
		if err != nil {
			return Page[Detection]{}, err
		}
		return pageFromAPI(result, detectionFromAPI), nil
	},
})

func (input DetectionsListInput) filters(client *api.Client, org string) (url.Values, error) {
	q := url.Values{}
	if err := addSeverityFilters(q, input.Severity); err != nil {
		return nil, err
	}
	addEach(q, "asset", input.Asset)
	if err := addAssigneeFilters(client, org, q, input.Assignee); err != nil {
		return nil, err
	}
	setIf(q, "status", input.Status)
	setBoolPtr(q, "has_assignee", input.HasAssignee)
	setIf(q, "q", input.Query)
	setIf(q, "detected_at", input.DetectedAt)
	if err := ValidateOrderBy[schema.DetectionsListParamsOrderBy](string(input.OrderBy)); err != nil {
		return nil, err
	}
	setIf(q, "order_by", string(input.OrderBy))
	return q, nil
}

type DetectionsGetInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"detection slug, e.g. DET-9C4"`
}

var DetectionsGet = Register(Operation[DetectionsGetInput, Detection]{
	Name:        "detections.get",
	Description: "Get a single SIEM detection by its slug. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input DetectionsGetInput) (Detection, error) {
		org, err := input.require()
		if err != nil {
			return Detection{}, err
		}
		if input.Slug == "" {
			return Detection{}, fmt.Errorf("slug is required")
		}
		detection, err := client.GetDetection(org, input.Slug)
		if err != nil {
			return Detection{}, err
		}
		return detectionFromAPI(*detection), nil
	},
})
