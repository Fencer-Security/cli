package api

import (
	"bytes"
	"encoding/json"
	"fmt"

	"fencer/cli/api/schema"
)

type assignBody struct {
	UserID *int `json:"user_id"`
}

func marshalAssign(userID *int) ([]byte, error) {
	return json.Marshal(assignBody{UserID: userID})
}

func vulnerabilityIgnoreBody(reason, notes string) (schema.VulnerabilityIgnore, error) {
	body := schema.VulnerabilityIgnore{}
	if notes != "" {
		body.IgnoredNotes = &notes
	}
	if reason != "" {
		var ignored schema.VulnerabilityIgnore_IgnoredReason
		if err := ignored.FromIgnoredReasonEnum(schema.IgnoredReasonEnum(reason)); err != nil {
			return body, err
		}
		body.IgnoredReason = &ignored
	}
	return body, nil
}

func vulnerabilityDeferBody(days int, reason, notes string) (schema.VulnerabilityDefer, error) {
	deferDays := schema.DeferDaysEnum(days)
	body := schema.VulnerabilityDefer{DeferDays: &deferDays}
	if notes != "" {
		body.IgnoredNotes = &notes
	}
	if reason != "" {
		var ignored schema.VulnerabilityDefer_IgnoredReason
		if err := ignored.FromIgnoredReasonEnum(schema.IgnoredReasonEnum(reason)); err != nil {
			return body, err
		}
		body.IgnoredReason = &ignored
	}
	return body, nil
}

// GetCurrentUser returns the org-scoped current user.
func (c *Client) GetCurrentUser(orgSlug string) (*CurrentUser, error) {
	req, err := schema.NewCurrentUserRetrieveRequest(c.BaseURL, orgSlug)
	if err != nil {
		return nil, err
	}
	var user CurrentUser
	if err := c.do(req, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// ListOrgUsers returns a page of organization members, optionally filtered by search.
func (c *Client) ListOrgUsers(orgSlug, search string, opts ListOptions) (*Paginated[OrgUser], error) {
	req, err := schema.NewOrganizationUsersListRequest(c.BaseURL, orgSlug, nil)
	if err != nil {
		return nil, err
	}
	q := opts.queryValues()
	if search != "" {
		q.Set("search", search)
	}
	applyQuery(req, q)
	var resp PaginatedResponse[OrgUser]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}

// AssignVulnerability assigns (or unassigns with nil userID) a vulnerability.
func (c *Client) AssignVulnerability(orgSlug, vulnSlug string, userID *int) (*Vulnerability, error) {
	payload, err := marshalAssign(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	req, err := schema.NewVulnerabilitiesAssignRequestWithBody(c.BaseURL, orgSlug, vulnSlug, jsonContentType, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	var vuln Vulnerability
	if err := c.do(req, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// IgnoreVulnerability marks a vulnerability as ignored with an optional reason and notes.
func (c *Client) IgnoreVulnerability(orgSlug, vulnSlug, reason, notes string) (*Vulnerability, error) {
	body, err := vulnerabilityIgnoreBody(reason, notes)
	if err != nil {
		return nil, err
	}
	req, err := schema.NewVulnerabilitiesIgnoreRequestWithApplicationVndFencerV1PlusJSONBody(c.BaseURL, orgSlug, vulnSlug, body)
	if err != nil {
		return nil, err
	}
	var vuln Vulnerability
	if err := c.do(req, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// UnignoreVulnerability clears the ignored state.
func (c *Client) UnignoreVulnerability(orgSlug, vulnSlug string) (*Vulnerability, error) {
	req, err := schema.NewVulnerabilitiesUnignoreRequest(c.BaseURL, orgSlug, vulnSlug)
	if err != nil {
		return nil, err
	}
	var vuln Vulnerability
	if err := c.do(req, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// DeferVulnerability snoozes a vulnerability for a preset number of days.
func (c *Client) DeferVulnerability(orgSlug, vulnSlug string, days int, reason, notes string) (*Vulnerability, error) {
	body, err := vulnerabilityDeferBody(days, reason, notes)
	if err != nil {
		return nil, err
	}
	req, err := schema.NewVulnerabilitiesDeferRequestWithApplicationVndFencerV1PlusJSONBody(c.BaseURL, orgSlug, vulnSlug, body)
	if err != nil {
		return nil, err
	}
	var vuln Vulnerability
	if err := c.do(req, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// UndeferVulnerability clears the deferred state.
func (c *Client) UndeferVulnerability(orgSlug, vulnSlug string) (*Vulnerability, error) {
	req, err := schema.NewVulnerabilitiesUndeferRequest(c.BaseURL, orgSlug, vulnSlug)
	if err != nil {
		return nil, err
	}
	var vuln Vulnerability
	if err := c.do(req, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// SetVulnerabilityPriority sets the priority level on a vulnerability.
func (c *Client) SetVulnerabilityPriority(orgSlug, vulnSlug, level string) (*Vulnerability, error) {
	priority := schema.PriorityLevelEnum(level)
	body := schema.PatchedUpdatePriority{PriorityLevel: &priority}
	req, err := schema.NewVulnerabilitiesPriorityPartialUpdateRequestWithApplicationVndFencerV1PlusJSONBody(c.BaseURL, orgSlug, vulnSlug, body)
	if err != nil {
		return nil, err
	}
	var vuln Vulnerability
	if err := c.do(req, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// GetVulnerabilityFixerInstructions returns a preview of what the fixer will do.
func (c *Client) GetVulnerabilityFixerInstructions(orgSlug, vulnSlug string) (*FixerInstructions, error) {
	req, err := schema.NewVulnerabilitiesFixerInstructionsRequest(c.BaseURL, orgSlug, vulnSlug)
	if err != nil {
		return nil, err
	}
	var instructions FixerInstructions
	if err := c.do(req, &instructions); err != nil {
		return nil, err
	}
	return &instructions, nil
}

// ExecuteVulnerabilityFixer schedules an automatic fix attempt for a vulnerability.
func (c *Client) ExecuteVulnerabilityFixer(orgSlug, vulnSlug string) (*FixerExecuteResponse, error) {
	req, err := schema.NewVulnerabilitiesFixerExecuteRequest(c.BaseURL, orgSlug, vulnSlug)
	if err != nil {
		return nil, err
	}
	var resp FixerExecuteResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AssignDetection assigns (or unassigns with nil userID) a detection.
func (c *Client) AssignDetection(orgSlug, detectionSlug string, userID *int) (*Detection, error) {
	payload, err := marshalAssign(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	req, err := schema.NewDetectionsAssignRequestWithBody(c.BaseURL, orgSlug, detectionSlug, jsonContentType, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	var d Detection
	if err := c.do(req, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// TransitionDetection changes a detection's status.
func (c *Client) TransitionDetection(orgSlug, detectionSlug, status string) (*Detection, error) {
	body := schema.DetectionTransition{Status: schema.DetectionStatusEnum(status)}
	req, err := schema.NewDetectionsTransitionRequestWithApplicationVndFencerV1PlusJSONBody(c.BaseURL, orgSlug, detectionSlug, body)
	if err != nil {
		return nil, err
	}
	var d Detection
	if err := c.do(req, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// GetOrganizations returns a page of organizations accessible to the current user.
func (c *Client) GetOrganizations(opts ListOptions) (*Paginated[Organization], error) {
	req, err := schema.NewOrganizationsListRequest(c.BaseURL, nil)
	if err != nil {
		return nil, err
	}
	applyQuery(req, opts.queryValues())
	var resp PaginatedResponse[Organization]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}

// GetVulnerabilities returns a page of vulnerabilities for the given organization slug.
func (c *Client) GetVulnerabilities(orgSlug string, opts ListOptions) (*Paginated[Vulnerability], error) {
	req, err := schema.NewVulnerabilitiesListRequest(c.BaseURL, orgSlug, nil)
	if err != nil {
		return nil, err
	}
	applyQuery(req, opts.queryValues())
	var resp PaginatedResponse[Vulnerability]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}

// GetVulnerability returns a single vulnerability by slug.
func (c *Client) GetVulnerability(orgSlug string, slug string) (*Vulnerability, error) {
	req, err := schema.NewVulnerabilitiesRetrieveRequest(c.BaseURL, orgSlug, slug)
	if err != nil {
		return nil, err
	}
	var vuln Vulnerability
	if err := c.do(req, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

// GetDetections returns a page of detections for the given organization slug.
func (c *Client) GetDetections(orgSlug string, opts ListOptions) (*Paginated[Detection], error) {
	req, err := schema.NewDetectionsListRequest(c.BaseURL, orgSlug, nil)
	if err != nil {
		return nil, err
	}
	applyQuery(req, opts.queryValues())
	var resp PaginatedResponse[Detection]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}

// GetDetection returns a single detection by slug.
func (c *Client) GetDetection(orgSlug string, slug string) (*Detection, error) {
	req, err := schema.NewDetectionsRetrieveRequest(c.BaseURL, orgSlug, slug)
	if err != nil {
		return nil, err
	}
	var detection Detection
	if err := c.do(req, &detection); err != nil {
		return nil, err
	}
	return &detection, nil
}

// GetAssets returns a page of asset inventory items for the given organization slug.
func (c *Client) GetAssets(orgSlug string, opts ListOptions) (*Paginated[AssetResource], error) {
	req, err := schema.NewAssetInventoryListRequest(c.BaseURL, orgSlug, nil)
	if err != nil {
		return nil, err
	}
	applyQuery(req, opts.queryValues())
	var resp PaginatedResponse[AssetResource]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}

// GetAssetInventoryConfig returns the asset inventory filter configuration for an
// organization, including the valid values for each filterable field (kind,
// provider, account, category, region). Only values present in the org's current
// asset graph are returned.
func (c *Client) GetAssetInventoryConfig(orgSlug string) (*AssetInventoryConfig, error) {
	req, err := schema.NewAssetInventoryConfigRequest(c.BaseURL, orgSlug)
	if err != nil {
		return nil, err
	}
	var cfg AssetInventoryConfig
	if err := c.do(req, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetAssetResource returns a single asset inventory item by slug.
func (c *Client) GetAssetResource(orgSlug, assetSlug string) (*AssetResource, error) {
	req, err := schema.NewAssetInventoryRetrieveRequest(c.BaseURL, orgSlug, assetSlug)
	if err != nil {
		return nil, err
	}
	var asset AssetResource
	if err := c.do(req, &asset); err != nil {
		return nil, err
	}
	return &asset, nil
}

// SetAssetCriticality sets the criticality score (0-100) on an asset resource
// identified by its slug.
func (c *Client) SetAssetCriticality(orgSlug, assetSlug string, criticality int) (*AssetResource, error) {
	body := schema.PatchedAssetResourceWrite{Criticality: &criticality}
	req, err := schema.NewAssetInventoryPartialUpdateRequestWithApplicationVndFencerV1PlusJSONBody(c.BaseURL, orgSlug, assetSlug, body)
	if err != nil {
		return nil, err
	}
	var asset AssetResource
	if err := c.do(req, &asset); err != nil {
		return nil, err
	}
	return &asset, nil
}

// GetAssetScans returns a page of scans for an asset identified by its AssetResource slug.
func (c *Client) GetAssetScans(orgSlug, assetSlug string, opts ListOptions) (*Paginated[Scan], error) {
	req, err := schema.NewAssetInventoryScansRequest(c.BaseURL, orgSlug, assetSlug, nil)
	if err != nil {
		return nil, err
	}
	applyQuery(req, opts.queryValues())
	var resp PaginatedResponse[Scan]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}

// ScheduleScan triggers a manual scan of an asset identified by its AssetResource slug.
// branch is only meaningful for repository assets and is ignored otherwise by the server.
func (c *Client) ScheduleScan(orgSlug, assetSlug, branch string) (*TriggerScanResponse, error) {
	body := schema.TriggerScan{}
	if branch != "" {
		body.Branch = &branch
	}
	req, err := schema.NewAssetInventoryTriggerScanRequestWithApplicationVndFencerV1PlusJSONBody(c.BaseURL, orgSlug, assetSlug, body)
	if err != nil {
		return nil, err
	}
	var resp TriggerScanResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetScan returns the unified scan detail for any scan type.
func (c *Client) GetScan(orgSlug string, scanSlug string) (*ScanDetail, error) {
	req, err := schema.NewScansRetrieveRequest(c.BaseURL, orgSlug, scanSlug)
	if err != nil {
		return nil, err
	}
	var detail ScanDetail
	if err := c.do(req, &detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

// GetScanVulnerabilities returns a page of vulnerability snapshots for a scan.
func (c *Client) GetScanVulnerabilities(orgSlug string, scanSlug string, opts ListOptions) (*Paginated[VulnerabilitySnapshot], error) {
	req, err := schema.NewScanVulnerabilitySnapshotsListRequest(c.BaseURL, orgSlug, scanSlug, nil)
	if err != nil {
		return nil, err
	}
	applyQuery(req, opts.queryValues())
	var resp PaginatedResponse[VulnerabilitySnapshot]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}

// GetIdentities returns a page of identities for the given organization slug.
func (c *Client) GetIdentities(orgSlug string, opts ListOptions) (*Paginated[Identity], error) {
	req, err := schema.NewIdentitiesListRequest(c.BaseURL, orgSlug, nil)
	if err != nil {
		return nil, err
	}
	applyQuery(req, opts.queryValues())
	var resp PaginatedResponse[Identity]
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return newPaginated(opts, resp), nil
}
