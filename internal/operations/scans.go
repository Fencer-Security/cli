package operations

import (
	"context"
	"fmt"
	"net/url"

	"fencer/cli/api"
	"fencer/cli/api/schema"
)

type Scan struct {
	Slug                 string `json:"slug"`
	Status               string `json:"status"`
	CreatedAt            string `json:"created_at"`
	TriggerType          string `json:"trigger_type"`
	TriggerByName        string `json:"trigger_by_name"`
	TriggerDescription   string `json:"trigger_description"`
	Branch               string `json:"branch"`
	CountVulnerabilities int    `json:"count_vulnerabilities"`
	CountNew             int    `json:"count_new"`
	CountCritical        int    `json:"count_critical"`
	CountHigh            int    `json:"count_high"`
	HasFailedChecks      bool   `json:"has_failed_checks"`
	FailedReason         string `json:"failed_reason"`
}

func scanFromAPI(s api.Scan) Scan {
	return Scan{
		Slug:                 s.Slug,
		Status:               s.Status,
		CreatedAt:            s.CreatedAt,
		TriggerType:          s.TriggerType,
		TriggerByName:        s.TriggerByName,
		TriggerDescription:   s.TriggerDescription,
		Branch:               s.Branch,
		CountVulnerabilities: s.CountVulnerabilities,
		CountNew:             s.CountNew,
		CountCritical:        s.CountCritical,
		CountHigh:            s.CountHigh,
		HasFailedChecks:      s.HasFailedChecks,
		FailedReason:         s.FailedReason,
	}
}

type ScansListInput struct {
	OrganizationInput
	PageInput
	Asset  string `json:"asset" jsonschema:"asset slug, e.g. ARES-AJ3"`
	Branch string `json:"branch,omitempty" jsonschema:"filter scans by branch"`
}

var ScansList = Register(Operation[ScansListInput, Page[Scan]]{
	Name:        "scans.list",
	Description: "List scans for a given asset. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input ScansListInput) (Page[Scan], error) {
		org, err := input.require()
		if err != nil {
			return Page[Scan]{}, err
		}
		if input.Asset == "" {
			return Page[Scan]{}, fmt.Errorf("asset is required")
		}
		filters := url.Values{}
		setIf(filters, "branch", input.Branch)
		opts, err := listOptions(input.PageInput, filters)
		if err != nil {
			return Page[Scan]{}, err
		}
		result, err := client.GetAssetScans(org, input.Asset, opts)
		if err != nil {
			return Page[Scan]{}, err
		}
		return pageFromAPI(result, scanFromAPI), nil
	},
})

type ScanCounts struct {
	CountNew          int `json:"count_new"`
	CountExisting     int `json:"count_existing"`
	CountOpen         int `json:"count_open"`
	CountResolved     int `json:"count_resolved"`
	CountIgnored      int `json:"count_ignored"`
	CountCriticalHigh int `json:"count_critical_high"`
}

type ScanDetail struct {
	Slug               string     `json:"slug"`
	Status             string     `json:"status"`
	QueuedAt           string     `json:"queued_at"`
	StartedAt          string     `json:"started_at"`
	FinishedAt         string     `json:"finished_at"`
	DurationSeconds    *float64   `json:"duration_seconds"`
	AssetType          string     `json:"asset_type"`
	AssetName          string     `json:"asset_name"`
	Branch             string     `json:"branch"`
	TriggerType        string     `json:"trigger_type"`
	TriggerDescription string     `json:"trigger_description"`
	FailedReason       string     `json:"failed_reason"`
	ErrorSuggestion    string     `json:"error_suggestion"`
	Counts             ScanCounts `json:"counts"`
}

func scanDetailFromAPI(s api.ScanDetail) ScanDetail {
	return ScanDetail{
		Slug:               s.Slug,
		Status:             s.Status,
		QueuedAt:           s.QueuedAt,
		StartedAt:          s.StartedAt,
		FinishedAt:         s.FinishedAt,
		DurationSeconds:    s.DurationSeconds,
		AssetType:          s.AssetType,
		AssetName:          s.AssetName,
		Branch:             s.Branch,
		TriggerType:        s.TriggerType,
		TriggerDescription: s.TriggerDescription,
		FailedReason:       s.FailedReason,
		ErrorSuggestion:    s.ErrorSuggestion,
		Counts: ScanCounts{
			CountNew:          s.Counts.CountNew,
			CountExisting:     s.Counts.CountExisting,
			CountOpen:         s.Counts.CountOpen,
			CountResolved:     s.Counts.CountResolved,
			CountIgnored:      s.Counts.CountIgnored,
			CountCriticalHigh: s.Counts.CountCriticalHigh,
		},
	}
}

type ScansGetInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"scan slug, e.g. SCAN-9RG (numeric IDs still work)"`
}

var ScansGet = Register(Operation[ScansGetInput, ScanDetail]{
	Name:        "scans.get",
	Description: "Get a scan by slug, including timing, trigger, and vulnerability counts. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input ScansGetInput) (ScanDetail, error) {
		org, err := input.require()
		if err != nil {
			return ScanDetail{}, err
		}
		if input.Slug == "" {
			return ScanDetail{}, fmt.Errorf("slug is required")
		}
		scan, err := client.GetScan(org, input.Slug)
		if err != nil {
			return ScanDetail{}, err
		}
		return scanDetailFromAPI(*scan), nil
	},
})

type VulnerabilitySnapshot struct {
	Slug          string `json:"slug"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Severity      int    `json:"severity"`
	Category      string `json:"category"`
	Status        string `json:"status"`
	DisplayStatus string `json:"display_status"`
	New           bool   `json:"new"`
	Resolved      bool   `json:"resolved"`
	Ignored       bool   `json:"ignored"`
	Live          bool   `json:"live"`
	AssetType     string `json:"asset_type"`
	AssetName     string `json:"asset_name"`
	LocationTitle string `json:"location_title"`
	FirstSeen     string `json:"first_seen"`
}

func snapshotFromAPI(s api.VulnerabilitySnapshot) VulnerabilitySnapshot {
	return VulnerabilitySnapshot{
		Slug:          s.Slug,
		Title:         s.Title,
		Description:   s.Description,
		Severity:      s.Severity,
		Category:      s.Category,
		Status:        s.Status,
		DisplayStatus: s.DisplayStatus,
		New:           s.New,
		Resolved:      s.Resolved,
		Ignored:       s.Ignored,
		Live:          s.Live,
		AssetType:     s.AssetType,
		AssetName:     s.AssetName,
		LocationTitle: s.LocationTitle,
		FirstSeen:     s.FirstSeen,
	}
}

type ScansListVulnerabilitiesInput struct {
	OrganizationInput
	PageInput
	Slug     string                    `json:"slug" jsonschema:"scan slug, e.g. SCAN-9RG (numeric IDs still work)"`
	New      *bool                     `json:"new,omitempty" jsonschema:"filter for findings new in this scan"`
	Resolved *bool                     `json:"resolved,omitempty" jsonschema:"filter for findings resolved by this scan"`
	Ignored  *bool                     `json:"ignored,omitempty" jsonschema:"filter for ignored findings"`
	Severity []string                  `json:"severity,omitempty" jsonschema:"severity filter(s): critical|high|medium|low|info or 0-4"`
	Status   string                    `json:"status,omitempty" jsonschema:"filter by status"`
	Category ScanVulnerabilityCategory `json:"category,omitempty"`
	Query    string                    `json:"q,omitempty" jsonschema:"text search across description and slug"`
	OrderBy  ScanVulnerabilityOrderBy  `json:"order_by,omitempty"`
}

var ScansListVulnerabilities = Register(Operation[ScansListVulnerabilitiesInput, Page[VulnerabilitySnapshot]]{
	Name:        "scans.list_vulnerabilities",
	Description: "List vulnerabilities found by a scan, with optional filters. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input ScansListVulnerabilitiesInput) (Page[VulnerabilitySnapshot], error) {
		org, err := input.require()
		if err != nil {
			return Page[VulnerabilitySnapshot]{}, err
		}
		if input.Slug == "" {
			return Page[VulnerabilitySnapshot]{}, fmt.Errorf("slug is required")
		}
		filters, err := input.filters()
		if err != nil {
			return Page[VulnerabilitySnapshot]{}, err
		}
		opts, err := listOptions(input.PageInput, filters)
		if err != nil {
			return Page[VulnerabilitySnapshot]{}, err
		}
		result, err := client.GetScanVulnerabilities(org, input.Slug, opts)
		if err != nil {
			return Page[VulnerabilitySnapshot]{}, err
		}
		return pageFromAPI(result, snapshotFromAPI), nil
	},
})

func (input ScansListVulnerabilitiesInput) filters() (url.Values, error) {
	q := url.Values{}
	if err := addSeverityFilters(q, input.Severity); err != nil {
		return nil, err
	}
	setBoolPtr(q, "new", input.New)
	setBoolPtr(q, "resolved", input.Resolved)
	setBoolPtr(q, "ignored", input.Ignored)
	setIf(q, "status", input.Status)
	if err := ValidateEnum[schema.ScanVulnerabilitySnapshotsListParamsCategory](string(input.Category)); err != nil {
		return nil, err
	}
	setIf(q, "category", string(input.Category))
	setIf(q, "q", input.Query)
	if err := ValidateOrderBy[schema.ScanVulnerabilitySnapshotsListParamsOrderBy](string(input.OrderBy)); err != nil {
		return nil, err
	}
	setIf(q, "order_by", string(input.OrderBy))
	return q, nil
}

type ScansDiffInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"scan slug, e.g. SCAN-9RG (numeric IDs still work)"`
}

type ScanDiff struct {
	Slug          string                  `json:"slug"`
	New           []VulnerabilitySnapshot `json:"new"`
	Resolved      []VulnerabilitySnapshot `json:"resolved"`
	NewCount      int                     `json:"new_count"`
	ResolvedCount int                     `json:"resolved_count"`
}

var ScansDiff = Register(Operation[ScansDiffInput, ScanDiff]{
	Name:        "scans.diff",
	Description: "Show every vulnerability new in and resolved by a scan. Walks all result pages. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(ctx context.Context, client *api.Client, input ScansDiffInput) (ScanDiff, error) {
		if _, err := input.require(); err != nil {
			return ScanDiff{}, err
		}
		if input.Slug == "" {
			return ScanDiff{}, fmt.Errorf("slug is required")
		}
		newTrue := true
		resolvedTrue := true
		newResults, err := collectAllPages(func(page, pageSize int) (Page[VulnerabilitySnapshot], error) {
			return ScansListVulnerabilities.Execute(ctx, client, ScansListVulnerabilitiesInput{
				OrganizationInput: input.OrganizationInput,
				PageInput:         PageInput{Page: page, PageSize: pageSize},
				Slug:              input.Slug,
				New:               &newTrue,
			})
		})
		if err != nil {
			return ScanDiff{}, err
		}
		resolvedResults, err := collectAllPages(func(page, pageSize int) (Page[VulnerabilitySnapshot], error) {
			return ScansListVulnerabilities.Execute(ctx, client, ScansListVulnerabilitiesInput{
				OrganizationInput: input.OrganizationInput,
				PageInput:         PageInput{Page: page, PageSize: pageSize},
				Slug:              input.Slug,
				Resolved:          &resolvedTrue,
			})
		})
		if err != nil {
			return ScanDiff{}, err
		}
		return ScanDiff{
			Slug:          input.Slug,
			New:           newResults,
			Resolved:      resolvedResults,
			NewCount:      len(newResults),
			ResolvedCount: len(resolvedResults),
		}, nil
	},
})

type ScansScheduleInput struct {
	OrganizationInput
	Slug   string `json:"slug" jsonschema:"asset slug, e.g. ARES-AJ3"`
	Branch string `json:"branch,omitempty" jsonschema:"branch to scan (repository assets only)"`
}

type ScanScheduleResult struct {
	Message string  `json:"message"`
	Slug    *string `json:"slug,omitempty"`
}

var ScansSchedule = Register(Operation[ScansScheduleInput, ScanScheduleResult]{
	Name:        "scans.schedule",
	Description: "Schedule a manual scan of an asset.",
	Safety:      SafetyMutating,
	Idempotent:  false,
	Scopes:      []string{ScopeAPIWrite},
	run: func(_ context.Context, client *api.Client, input ScansScheduleInput) (ScanScheduleResult, error) {
		org, err := input.require()
		if err != nil {
			return ScanScheduleResult{}, err
		}
		if input.Slug == "" {
			return ScanScheduleResult{}, fmt.Errorf("slug is required")
		}
		resp, err := client.ScheduleScan(org, input.Slug, input.Branch)
		if err != nil {
			return ScanScheduleResult{}, err
		}
		return ScanScheduleResult{Message: resp.Message, Slug: resp.Slug}, nil
	},
})
