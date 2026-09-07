package operations

import (
	"context"
	"fmt"

	"fencer/cli/api"
)

type DetectionsAssignInput struct {
	OrganizationInput
	Slug  string `json:"slug" jsonschema:"detection slug"`
	Email string `json:"email,omitempty" jsonschema:"assign to this organization member email"`
	Me    bool   `json:"me,omitempty" jsonschema:"assign to the authenticated user"`
}

var DetectionsAssign = Register(Operation[DetectionsAssignInput, Detection]{
	Name:        "detections.assign",
	Description: "Assign a detection to an organization member.",
	Safety:      SafetyMutating,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIWrite},
	run: func(_ context.Context, client *api.Client, input DetectionsAssignInput) (Detection, error) {
		org, err := input.require()
		if err != nil {
			return Detection{}, err
		}
		if input.Slug == "" {
			return Detection{}, fmt.Errorf("slug is required")
		}
		userID, _, err := ResolveUserID(client, org, input.Email, input.Me)
		if err != nil {
			return Detection{}, err
		}
		d, err := client.AssignDetection(org, input.Slug, &userID)
		if err != nil {
			return Detection{}, err
		}
		return detectionFromAPI(*d), nil
	},
})

type DetectionsUnassignInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"detection slug"`
}

type DetectionsUnassignOutput struct {
	Detection         Detection `json:"detection"`
	AlreadyUnassigned bool      `json:"already_unassigned"`
	PreviousAssignee  string    `json:"previous_assignee,omitempty"`
}

var DetectionsUnassign = Register(Operation[DetectionsUnassignInput, DetectionsUnassignOutput]{
	Name:        "detections.unassign",
	Description: "Clear a detection's assignee.",
	Safety:      SafetyMutating,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIWrite},
	run: func(_ context.Context, client *api.Client, input DetectionsUnassignInput) (DetectionsUnassignOutput, error) {
		org, err := input.require()
		if err != nil {
			return DetectionsUnassignOutput{}, err
		}
		if input.Slug == "" {
			return DetectionsUnassignOutput{}, fmt.Errorf("slug is required")
		}
		current, err := client.GetDetection(org, input.Slug)
		if err != nil {
			return DetectionsUnassignOutput{}, err
		}
		if current.AssigneeEmail == "" {
			return DetectionsUnassignOutput{
				Detection:         detectionFromAPI(*current),
				AlreadyUnassigned: true,
			}, nil
		}
		d, err := client.AssignDetection(org, input.Slug, nil)
		if err != nil {
			return DetectionsUnassignOutput{}, err
		}
		return DetectionsUnassignOutput{
			Detection:        detectionFromAPI(*d),
			PreviousAssignee: current.AssigneeEmail,
		}, nil
	},
})

func transitionDetection(client *api.Client, org, slug, status string) (Detection, error) {
	if slug == "" {
		return Detection{}, fmt.Errorf("slug is required")
	}
	d, err := client.TransitionDetection(org, slug, status)
	if err != nil {
		return Detection{}, err
	}
	return detectionFromAPI(*d), nil
}

type DetectionsInvestigateInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"detection slug"`
}

var DetectionsInvestigate = Register(Operation[DetectionsInvestigateInput, Detection]{
	Name:        "detections.investigate",
	Description: "Mark a detection as under investigation.",
	Safety:      SafetyMutating,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIWrite},
	run: func(_ context.Context, client *api.Client, input DetectionsInvestigateInput) (Detection, error) {
		org, err := input.require()
		if err != nil {
			return Detection{}, err
		}
		return transitionDetection(client, org, input.Slug, "under_investigation")
	},
})

func DetectionResolveStatus(as string) (string, error) {
	switch as {
	case "false-positive":
		return "resolved_false_positive", nil
	case "true-positive":
		return "resolved_true_positive", nil
	default:
		return "", fmt.Errorf("as must be one of false-positive, true-positive")
	}
}

type DetectionsResolveInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"detection slug"`
	As   string `json:"as" jsonschema:"false-positive or true-positive"`
}

var DetectionsResolve = Register(Operation[DetectionsResolveInput, Detection]{
	Name:        "detections.resolve",
	Description: "Resolve a detection as a false positive or true positive.",
	Safety:      SafetyMutating,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIWrite},
	run: func(_ context.Context, client *api.Client, input DetectionsResolveInput) (Detection, error) {
		org, err := input.require()
		if err != nil {
			return Detection{}, err
		}
		status, err := DetectionResolveStatus(input.As)
		if err != nil {
			return Detection{}, err
		}
		return transitionDetection(client, org, input.Slug, status)
	},
})

type DetectionsReopenInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"detection slug"`
}

var DetectionsReopen = Register(Operation[DetectionsReopenInput, Detection]{
	Name:        "detections.reopen",
	Description: "Re-open a detection by transitioning it back to new.",
	Safety:      SafetyMutating,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIWrite},
	run: func(_ context.Context, client *api.Client, input DetectionsReopenInput) (Detection, error) {
		org, err := input.require()
		if err != nil {
			return Detection{}, err
		}
		return transitionDetection(client, org, input.Slug, "new")
	},
})
