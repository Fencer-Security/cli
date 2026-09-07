package operations

import (
	"fmt"
	"net/url"

	"fencer/cli/api"
)

const (
	DefaultPageSize = 50
	MaxPageSize     = 1000
	maxPageFetches  = 100
)

// PageInput is the shared pagination input for list operations.
type PageInput struct {
	Page     int `json:"page,omitempty" jsonschema:"1-indexed page number (default 1)"`
	PageSize int `json:"page_size,omitempty" jsonschema:"results per page (default 50, server max 1000)"`
}

// Normalized returns 1-indexed page and page-size defaults used by list operations.
func (p PageInput) Normalized() (page, pageSize int, err error) {
	page = p.Page
	if page == 0 {
		page = 1
	}
	if page < 1 {
		return 0, 0, fmt.Errorf("page must be >= 1")
	}
	pageSize = p.PageSize
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}
	if pageSize < 1 || pageSize > MaxPageSize {
		return 0, 0, fmt.Errorf("page_size must be between 1 and %d", MaxPageSize)
	}
	return page, pageSize, nil
}

func listOptions(page PageInput, filters url.Values) (api.ListOptions, error) {
	p, s, err := page.Normalized()
	if err != nil {
		return api.ListOptions{}, err
	}
	return api.ListOptions{Page: p, PageSize: s, Filters: filters}, nil
}

// Pagination describes the position and size of one result page.
type Pagination struct {
	Page         int  `json:"page"`
	PageSize     int  `json:"page_size"`
	Count        int  `json:"count"`
	TotalPages   int  `json:"total_pages"`
	NextPage     *int `json:"next_page"`
	PreviousPage *int `json:"previous_page"`
}

// Page is the stable list-operation result shared by CLI JSON and MCP.
type Page[T any] struct {
	Results    []T        `json:"results"`
	Pagination Pagination `json:"pagination"`
}

func pageFromAPI[Source, Target any](page *api.Paginated[Source], convert func(Source) Target) Page[Target] {
	results := make([]Target, len(page.Results))
	for i, item := range page.Results {
		results[i] = convert(item)
	}
	return Page[Target]{
		Results: results,
		Pagination: Pagination{
			Page:         page.Page,
			PageSize:     page.PageSize,
			Count:        page.Count,
			TotalPages:   page.TotalPages,
			NextPage:     page.NextPage,
			PreviousPage: page.PreviousPage,
		},
	}
}

func collectAllPages[T any](fetch func(page, pageSize int) (Page[T], error)) ([]T, error) {
	var all []T
	page := 1
	for range maxPageFetches {
		result, err := fetch(page, MaxPageSize)
		if err != nil {
			return nil, err
		}
		all = append(all, result.Results...)
		if result.Pagination.NextPage == nil {
			if result.Pagination.Count > len(all) {
				return nil, fmt.Errorf("incomplete list: collected %d of %d", len(all), result.Pagination.Count)
			}
			return all, nil
		}
		next := *result.Pagination.NextPage
		if next <= page {
			return nil, fmt.Errorf("pagination did not advance (page %d -> %d)", page, next)
		}
		page = next
	}
	return nil, fmt.Errorf("list exceeded %d page fetches without completing", maxPageFetches)
}
