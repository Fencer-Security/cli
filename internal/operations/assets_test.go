package operations

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fencer/cli/api"
)

func TestAssetsList(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":1,"slug":"AR-9R4","kind_name":"Repo","description":"web","criticality":50}]}`)
	}))
	defer server.Close()

	topLevel := true
	result, err := AssetsList.Execute(context.Background(), api.New(server.URL, server.Client()), AssetsListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		PageInput:         PageInput{Page: 2, PageSize: 25},
		Search:            "web",
		Kind:              "cloud_account",
		TopLevel:          &topLevel,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/asset-inventory/" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{
		"page=2", "page_size=25", "search=web", "top_level=true",
		"include_vulnerability_count=false", "cloud_account",
	} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(result.Results) != 1 || result.Results[0].Slug != "AR-9R4" {
		t.Fatalf("unexpected results: %+v", result.Results)
	}
}

func TestAssetsGet(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":1,"slug":"AR-9R4","kind_name":"Application","provider_name":"Azure","category":"web","description":"checkout-service","belongs_to":"acme","asset_id":11,"asset_type":"application","criticality":80}`)
	}))
	defer server.Close()

	got, err := AssetsGet.Execute(context.Background(), api.New(server.URL, server.Client()), AssetsGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "AR-9R4",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/asset-inventory/AR-9R4/" {
		t.Fatalf("path = %q", gotPath)
	}
	if got.Slug != "AR-9R4" || got.AssetType != "application" || got.Criticality != 80 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestAssetsGetRequiresSlug(t *testing.T) {
	_, err := AssetsGet.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), AssetsGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing slug error")
	}
}

func TestAssetsListOrderingAlias(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":0,"next":null,"previous":null,"results":[]}`)
	}))
	defer server.Close()

	_, err := AssetsList.Execute(context.Background(), api.New(server.URL, server.Client()), AssetsListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Ordering:          "-description",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(query, "order_by=-description") {
		t.Fatalf("query %q missing order_by", query)
	}
}

func TestAssetsFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"filters":{"kind":{"label":"Asset Kind","type":"enum","options":[{"value":"cloud_account","label":"Cloud Account"}]}}}`)
	}))
	defer server.Close()

	all, err := AssetsFilters.Execute(context.Background(), api.New(server.URL, server.Client()), AssetsFiltersInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if all.Filters["kind"].Label != "Asset Kind" {
		t.Fatalf("unexpected filters: %+v", all.Filters)
	}

	kind, err := AssetsFilters.Execute(context.Background(), api.New(server.URL, server.Client()), AssetsFiltersInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Field:             "KIND",
	})
	if err != nil {
		t.Fatalf("execute field: %v", err)
	}
	if kind.Values == nil || kind.Values.Options[0].Value != "cloud_account" {
		t.Fatalf("unexpected values: %+v", kind.Values)
	}

	_, err = AssetsFilters.Execute(context.Background(), api.New(server.URL, server.Client()), AssetsFiltersInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Field:             "bogus",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown filter field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestAssetsSetCriticality(t *testing.T) {
	var gotPath, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":1,"slug":"AR-9R4","kind_name":"Repo","criticality":42}`)
	}))
	defer server.Close()

	got, err := AssetsSetCriticality.Execute(context.Background(), api.New(server.URL, server.Client()), AssetsSetCriticalityInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "AR-9R4",
		Score:             42,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/asset-inventory/AR-9R4/" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, `"criticality":42`) {
		t.Fatalf("body = %q", gotBody)
	}
	if got.Criticality != 42 {
		t.Fatalf("criticality = %d", got.Criticality)
	}
}

func TestAssetsSetCriticalityOutOfRange(t *testing.T) {
	_, err := AssetsSetCriticality.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), AssetsSetCriticalityInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "AR-9R4",
		Score:             101,
	})
	if err == nil {
		t.Fatal("expected out of range error")
	}
}
