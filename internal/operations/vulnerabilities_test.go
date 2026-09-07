package operations

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fencer/cli/api"
)

func TestVulnerabilitiesList(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":42,"slug":"vuln-abc","title":"SQL injection","severity":1,"status":"open","asset_resource_slug":"ARES-AJ3","asset_name":"web-app"}]}`)
	}))
	defer server.Close()

	live := true
	result, err := VulnerabilitiesList.Execute(context.Background(), api.New(server.URL, server.Client()), VulnerabilitiesListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		PageInput:         PageInput{Page: 2, PageSize: 25},
		Asset:             []string{"ARES-AJ3"},
		Severity:          []string{"critical", "high"},
		Live:              &live,
	})
	if err != nil {
		t.Fatalf("execute vulnerabilities.list: %v", err)
	}
	if gotPath != "/api/v1/org/acme/vulnerabilities/" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{"page=2", "page_size=25", "asset=ARES-AJ3", "severity=0", "severity=1", "live=true", "status=open"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(result.Results) != 1 || result.Results[0].Slug != "vuln-abc" {
		t.Fatalf("unexpected results: %+v", result.Results)
	}
}

func TestVulnerabilitiesListStatusAllOmitsFilter(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":0,"next":null,"previous":null,"results":[]}`)
	}))
	defer server.Close()

	_, err := VulnerabilitiesList.Execute(context.Background(), api.New(server.URL, server.Client()), VulnerabilitiesListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Status:            "all",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(query, "status=") {
		t.Fatalf("expected no status filter, got %q", query)
	}
}

func TestVulnerabilitiesListInvalidSeverity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected no request")
	}))
	defer server.Close()

	_, err := VulnerabilitiesList.Execute(context.Background(), api.New(server.URL, server.Client()), VulnerabilitiesListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Severity:          []string{"nope"},
	})
	if err == nil {
		t.Fatal("expected invalid severity error")
	}
}

func TestVulnerabilitiesListInvalidCategory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected no request")
	}))
	defer server.Close()

	_, err := VulnerabilitiesList.Execute(context.Background(), api.New(server.URL, server.Client()), VulnerabilitiesListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Category:          "not-a-category",
	})
	if err == nil {
		t.Fatal("expected invalid category error")
	}
}

func TestVulnerabilitiesGet(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":42,"slug":"vuln-abc","title":"SQL injection","severity":1,"status":"open"}`)
	}))
	defer server.Close()

	result, err := VulnerabilitiesGet.Execute(context.Background(), api.New(server.URL, server.Client()), VulnerabilitiesGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "vuln-abc",
	})
	if err != nil {
		t.Fatalf("execute vulnerabilities.get: %v", err)
	}
	if gotPath != "/api/v1/org/acme/vulnerabilities/vuln-abc/" {
		t.Fatalf("path = %q", gotPath)
	}
	if result.Slug != "vuln-abc" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVulnerabilitiesGetRequiresSlug(t *testing.T) {
	_, err := VulnerabilitiesGet.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), VulnerabilitiesGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing slug error")
	}
}
