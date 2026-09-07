package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"fencer/cli/api"
	"fencer/cli/api/schema"
)

type Asset struct {
	Slug         string `json:"slug"`
	KindName     string `json:"kind_name"`
	ProviderName string `json:"provider_name"`
	Category     string `json:"category"`
	Description  string `json:"description"`
	BelongsTo    string `json:"belongs_to"`
	AssetType    string `json:"asset_type"`
	Criticality  int    `json:"criticality"`
}

func assetFromAPI(a api.AssetResource) Asset {
	return Asset{
		Slug:         a.Slug,
		KindName:     a.KindName,
		ProviderName: a.ProviderName,
		Category:     a.Category,
		Description:  a.Description,
		BelongsTo:    a.BelongsTo,
		AssetType:    a.AssetType,
		Criticality:  a.Criticality,
	}
}

type assetInventoryFilter struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type AssetsListInput struct {
	OrganizationInput
	PageInput
	Search   string       `json:"search,omitempty" jsonschema:"text search across asset fields"`
	Kind     string       `json:"kind,omitempty" jsonschema:"filter by asset kind"`
	OrderBy  AssetOrderBy `json:"order_by,omitempty"`
	Ordering string       `json:"ordering,omitempty" jsonschema:"alias for order_by"`
	TopLevel *bool        `json:"top_level,omitempty" jsonschema:"only top-level assets"`
}

var AssetsList = Register(Operation[AssetsListInput, Page[Asset]]{
	Name:        "assets.list",
	Description: "List assets in the organization's asset inventory. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input AssetsListInput) (Page[Asset], error) {
		org, err := input.require()
		if err != nil {
			return Page[Asset]{}, err
		}
		filters, err := input.filters()
		if err != nil {
			return Page[Asset]{}, err
		}
		opts, err := listOptions(input.PageInput, filters)
		if err != nil {
			return Page[Asset]{}, err
		}
		result, err := client.GetAssets(org, opts)
		if err != nil {
			return Page[Asset]{}, err
		}
		return pageFromAPI(result, assetFromAPI), nil
	},
})

type AssetsGetInput struct {
	OrganizationInput
	Slug string `json:"slug" jsonschema:"asset slug, e.g. ARES-BDA"`
}

var AssetsGet = Register(Operation[AssetsGetInput, Asset]{
	Name:        "assets.get",
	Description: "Get a single asset from the inventory by its slug. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input AssetsGetInput) (Asset, error) {
		org, err := input.require()
		if err != nil {
			return Asset{}, err
		}
		if input.Slug == "" {
			return Asset{}, fmt.Errorf("slug is required")
		}
		asset, err := client.GetAssetResource(org, input.Slug)
		if err != nil {
			return Asset{}, err
		}
		return assetFromAPI(*asset), nil
	},
})

func (input AssetsListInput) filters() (url.Values, error) {
	q := url.Values{}
	q.Set("include_vulnerability_count", "false")
	setIf(q, "search", input.Search)
	orderBy := string(input.OrderBy)
	if orderBy == "" {
		orderBy = input.Ordering
	}
	if err := ValidateOrderBy[schema.AssetInventoryListParamsOrderBy](orderBy); err != nil {
		return nil, err
	}
	setIf(q, "order_by", orderBy)
	setBoolPtr(q, "top_level", input.TopLevel)
	if input.Kind != "" {
		encoded, err := json.Marshal([]assetInventoryFilter{
			{Key: "kind", Operator: "is", Values: []string{input.Kind}},
		})
		if err == nil {
			q.Set("filters", string(encoded))
		}
	}
	return q, nil
}

type FilterOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type FilterConfig struct {
	Label   string         `json:"label"`
	Type    string         `json:"type"`
	Options []FilterOption `json:"options"`
}

type AssetsFiltersInput struct {
	OrganizationInput
	Field string `json:"field,omitempty" jsonschema:"filter field name; omit to list fields"`
}

type AssetsFiltersOutput struct {
	Filters map[string]FilterConfig `json:"filters,omitempty"`
	Field   string                  `json:"field,omitempty"`
	Values  *FilterConfig           `json:"values,omitempty"`
}

var AssetsFilters = Register(Operation[AssetsFiltersInput, AssetsFiltersOutput]{
	Name:        "assets.filters",
	Description: "List asset inventory filter fields and their valid values. Read-only.",
	Safety:      SafetyReadOnly,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIRead},
	run: func(_ context.Context, client *api.Client, input AssetsFiltersInput) (AssetsFiltersOutput, error) {
		org, err := input.require()
		if err != nil {
			return AssetsFiltersOutput{}, err
		}
		cfg, err := client.GetAssetInventoryConfig(org)
		if err != nil {
			return AssetsFiltersOutput{}, err
		}
		filters := make(map[string]FilterConfig, len(cfg.Filters))
		for key, fc := range cfg.Filters {
			filters[key] = filterConfigFromAPI(fc)
		}
		if input.Field == "" {
			return AssetsFiltersOutput{Filters: filters}, nil
		}
		field := strings.ToLower(input.Field)
		values, ok := filters[field]
		if !ok {
			names := make([]string, 0, len(filters))
			for name := range filters {
				names = append(names, name)
			}
			sort.Strings(names)
			return AssetsFiltersOutput{}, fmt.Errorf("unknown filter field %q (available: %s)", input.Field, strings.Join(names, ", "))
		}
		return AssetsFiltersOutput{Field: field, Values: &values}, nil
	},
})

func filterConfigFromAPI(fc api.FilterConfig) FilterConfig {
	options := make([]FilterOption, len(fc.Options))
	for i, opt := range fc.Options {
		options[i] = FilterOption{Value: opt.Value, Label: opt.Label}
	}
	return FilterConfig{Label: fc.Label, Type: fc.Type, Options: options}
}

func ValidateCriticalityScore(score int) error {
	if score < 0 || score > 100 {
		return fmt.Errorf("score must be between 0 and 100")
	}
	return nil
}

type AssetsSetCriticalityInput struct {
	OrganizationInput
	Slug  string `json:"slug" jsonschema:"asset slug"`
	Score int    `json:"score" jsonschema:"criticality score from 0 to 100"`
}

var AssetsSetCriticality = Register(Operation[AssetsSetCriticalityInput, Asset]{
	Name:        "assets.set_criticality",
	Description: "Set the criticality score of an asset (0-100).",
	Safety:      SafetyMutating,
	Idempotent:  true,
	Scopes:      []string{ScopeAPIWrite},
	run: func(_ context.Context, client *api.Client, input AssetsSetCriticalityInput) (Asset, error) {
		org, err := input.require()
		if err != nil {
			return Asset{}, err
		}
		if input.Slug == "" {
			return Asset{}, fmt.Errorf("slug is required")
		}
		if err := ValidateCriticalityScore(input.Score); err != nil {
			return Asset{}, err
		}
		asset, err := client.SetAssetCriticality(org, input.Slug, input.Score)
		if err != nil {
			return Asset{}, err
		}
		return assetFromAPI(*asset), nil
	},
})
