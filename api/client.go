package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	acceptHeaderValue = "application/vnd.fencer.v1+json, application/json"
	jsonContentType   = "application/vnd.fencer.v1+json"
)

// Client is a thin HTTP client for the Fencer REST API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// New creates a new API client.
func New(baseURL string, httpClient *http.Client) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: httpClient,
	}
}

func (c *Client) do(req *http.Request, dest interface{}) error {
	req.Header.Set("Accept", acceptHeaderValue)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeResponse(resp, dest)
}

func applyQuery(req *http.Request, query url.Values) {
	if len(query) > 0 {
		req.URL.RawQuery = query.Encode()
	}
}

func (c *Client) newJSONRequest(method, path string, body interface{}) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", jsonContentType)
	}
	return req, nil
}

// Get performs a GET request and decodes the JSON response into dest.
func (c *Client) Get(path string, query url.Values, dest interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	applyQuery(req, query)
	return c.do(req, dest)
}

// Post performs a POST request. A nil body sends zero bytes and no Content-Type.
func (c *Client) Post(path string, body interface{}, dest interface{}) error {
	req, err := c.newJSONRequest(http.MethodPost, path, body)
	if err != nil {
		return err
	}
	return c.do(req, dest)
}

// Patch performs a PATCH request. A nil body sends zero bytes and no Content-Type.
func (c *Client) Patch(path string, body interface{}, dest interface{}) error {
	req, err := c.newJSONRequest(http.MethodPatch, path, body)
	if err != nil {
		return err
	}
	return c.do(req, dest)
}

// UpgradeRequiredError is returned when the server rejects the CLI version with 426.
type UpgradeRequiredError struct {
	Detail           string `json:"detail"`
	MinClientVersion string `json:"min_client_version"`
	DocsURL          string `json:"docs_url"`
}

func (e *UpgradeRequiredError) Error() string {
	msg := e.Detail
	if e.DocsURL != "" {
		msg += "\nUpgrade instructions: " + e.DocsURL
	}
	return msg
}

func decodeResponse(resp *http.Response, dest interface{}) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusUpgradeRequired {
		var upgradeErr UpgradeRequiredError
		if json.Unmarshal(body, &upgradeErr) == nil && upgradeErr.Detail != "" {
			return &upgradeErr
		}
		return fmt.Errorf("API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if dest == nil {
		return nil
	}

	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

// PaginatedResponse is a generic wrapper for paginated DRF list responses.
type PaginatedResponse[T any] struct {
	Count    int    `json:"count"`
	Next     string `json:"next"`
	Previous string `json:"previous"`
	Results  []T    `json:"results"`
}

// ListOptions carries pagination and filter parameters for list endpoints.
type ListOptions struct {
	Page     int
	PageSize int
	Filters  url.Values
}

func (o ListOptions) queryValues() url.Values {
	q := url.Values{}
	for k, v := range o.Filters {
		q[k] = v
	}
	if o.Page > 0 {
		q.Set("page", fmt.Sprintf("%d", o.Page))
	}
	if o.PageSize > 0 {
		q.Set("page_size", fmt.Sprintf("%d", o.PageSize))
	}
	return q
}

// Paginated is the CLI-facing result of a list call. Page numbers are computed
// from the DRF response so callers never need to parse next/previous URLs.
type Paginated[T any] struct {
	Results      []T
	Page         int
	PageSize     int
	Count        int
	TotalPages   int
	NextPage     *int
	PreviousPage *int
}

func newPaginated[T any](opts ListOptions, raw PaginatedResponse[T]) *Paginated[T] {
	page := opts.Page
	if page < 1 {
		page = 1
	}
	pageSize := opts.PageSize
	if pageSize < 1 {
		pageSize = len(raw.Results)
	}
	totalPages := 1
	if pageSize > 0 {
		totalPages = (raw.Count + pageSize - 1) / pageSize
		if totalPages < 1 {
			totalPages = 1
		}
	}
	var next, prev *int
	if raw.Next != "" {
		n := page + 1
		next = &n
	}
	if raw.Previous != "" {
		p := page - 1
		prev = &p
	}
	return &Paginated[T]{
		Results:      raw.Results,
		Page:         page,
		PageSize:     pageSize,
		Count:        raw.Count,
		TotalPages:   totalPages,
		NextPage:     next,
		PreviousPage: prev,
	}
}

// severityNames maps the SeverityEnum integer values to display strings.
var severityNames = map[int]string{
	0: "critical",
	1: "high",
	2: "medium",
	3: "low",
	4: "info",
}

// SeverityName returns the display string for a SeverityEnum value.
func SeverityName(v int) string {
	if s, ok := severityNames[v]; ok {
		return s
	}
	return fmt.Sprintf("%d", v)
}

// Organization represents a Fencer organization.
type Organization struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// CurrentUser is the org-scoped current-user payload (subset of fields).
type CurrentUser struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	IsAdmin     bool   `json:"is_admin"`
}

// OrgUser is a member of the organization.
type OrgUser struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// formatAssetURI renders a "<type>:<id>" identifier from the API's separate
// asset_type/asset_id fields. Returns "" when either component is missing.
func formatAssetURI(assetType string, assetID int) string {
	if assetType == "" || assetID == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", assetType, assetID)
}

// Vulnerability represents a Fencer vulnerability.
type Vulnerability struct {
	ID                int    `json:"id"`
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

// Detection represents a Fencer detection.
type Detection struct {
	ID            int    `json:"id"`
	Slug          string `json:"slug"`
	Title         string `json:"title"`
	Severity      int    `json:"severity"`
	Status        string `json:"status"`
	AssigneeEmail string `json:"assignee_email"`
	AssigneeName  string `json:"assignee_name"`
}

// AssetResource represents a Fencer asset inventory item.
type AssetResource struct {
	ID           int    `json:"id"`
	Slug         string `json:"slug"`
	KindName     string `json:"kind_name"`
	ProviderName string `json:"provider_name"`
	Category     string `json:"category"`
	Description  string `json:"description"`
	BelongsTo    string `json:"belongs_to"`
	Asset        string `json:"asset"`
	AssetID      int    `json:"-"`
	AssetType    string `json:"-"`
	Criticality  int    `json:"criticality"`
}

func (a *AssetResource) UnmarshalJSON(data []byte) error {
	type alias AssetResource
	aux := struct {
		AssetID   int    `json:"asset_id"`
		AssetType string `json:"asset_type"`
		*alias
	}{alias: (*alias)(a)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	a.AssetID = aux.AssetID
	a.AssetType = aux.AssetType
	a.Asset = formatAssetURI(aux.AssetType, aux.AssetID)
	return nil
}

// Scan is a row from a per-asset scan history list (ScanHistorySerializer).
type Scan struct {
	ID                   int    `json:"id"`
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

// ScanDetail is the unified scan retrieve payload (ScanDetailSerializer).
type ScanDetail struct {
	ID                 int        `json:"id"`
	Slug               string     `json:"slug"`
	Status             string     `json:"status"`
	QueuedAt           string     `json:"queued_at"`
	StartedAt          string     `json:"started_at"`
	FinishedAt         string     `json:"finished_at"`
	DurationSeconds    *float64   `json:"duration_seconds"`
	Asset              string     `json:"asset"`
	AssetType          string     `json:"-"`
	AssetName          string     `json:"asset_name"`
	Branch             string     `json:"branch"`
	TriggerType        string     `json:"trigger_type"`
	TriggerDescription string     `json:"trigger_description"`
	FailedReason       string     `json:"failed_reason"`
	ErrorSuggestion    string     `json:"error_suggestion"`
	Counts             ScanCounts `json:"counts"`
}

func (s *ScanDetail) UnmarshalJSON(data []byte) error {
	type alias ScanDetail
	aux := struct {
		AssetID   int    `json:"asset_id"`
		AssetType string `json:"asset_type"`
		*alias
	}{alias: (*alias)(s)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.AssetType = aux.AssetType
	s.Asset = formatAssetURI(aux.AssetType, aux.AssetID)
	return nil
}

// ScanCounts aggregates vulnerability tallies returned inside ScanDetail.
type ScanCounts struct {
	CountNew          int `json:"count_new"`
	CountExisting     int `json:"count_existing"`
	CountOpen         int `json:"count_open"`
	CountResolved     int `json:"count_resolved"`
	CountIgnored      int `json:"count_ignored"`
	CountCriticalHigh int `json:"count_critical_high"`
}

// VulnerabilitySnapshot is a row from a scan's vulnerability-snapshots list.
type VulnerabilitySnapshot struct {
	ID            int    `json:"id"`
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
	Asset         string `json:"asset"`
	AssetType     string `json:"-"`
	AssetName     string `json:"asset_name"`
	LocationTitle string `json:"location_title"`
	FirstSeen     string `json:"first_seen"`
}

func (v *VulnerabilitySnapshot) UnmarshalJSON(data []byte) error {
	type alias VulnerabilitySnapshot
	aux := struct {
		AssetID   int    `json:"asset_id"`
		AssetType string `json:"asset_type"`
		*alias
	}{alias: (*alias)(v)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	v.AssetType = aux.AssetType
	v.Asset = formatAssetURI(aux.AssetType, aux.AssetID)
	return nil
}

// Identity represents a Fencer identity.
type Identity struct {
	ID           int    `json:"id"`
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	IdentityType string `json:"identity_type"`
}

// FixerInstructions describes what an automatic fixer will do for a vulnerability.
type FixerInstructions struct {
	Kind          string `json:"kind"`
	Description   string `json:"description"`
	CLICommand    string `json:"cli_command"`
	SafeToExecute bool   `json:"safe_to_execute"`
}

// FixerExecuteResponse is returned after scheduling (or re-fetching) a fix attempt.
type FixerExecuteResponse struct {
	FixID      int    `json:"fix_id"`
	AttemptID  int    `json:"attempt_id"`
	Status     string `json:"status"`
	DetailsURL string `json:"details_url"`
}

// FilterOption is a single valid value for an asset inventory filter, paired with
// its human-readable label (e.g. value "cloud_account", label "Cloud Account").
type FilterOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// FilterConfig describes one filterable field exposed by the asset inventory
// config endpoint, including the set of valid values for it.
type FilterConfig struct {
	Label   string         `json:"label"`
	Type    string         `json:"type"`
	Options []FilterOption `json:"options"`
}

// AssetInventoryConfig is the subset of the asset-inventory config payload the CLI
// consumes: the per-field filter definitions and their valid values.
type AssetInventoryConfig struct {
	Filters map[string]FilterConfig `json:"filters"`
}

// TriggerScanResponse mirrors apps.scanners.api_serializers.TriggerScanResponseSerializer.
type TriggerScanResponse struct {
	Message string  `json:"message"`
	ScanID  *int    `json:"scan_id,omitempty"`
	Slug    *string `json:"slug,omitempty"`
}
