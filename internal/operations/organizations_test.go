package operations

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"fencer/cli/api"
)

func TestOrganizationsList(t *testing.T) {
	var gotPage, gotPageSize string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPage = r.URL.Query().Get("page")
		gotPageSize = r.URL.Query().Get("page_size")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":7,"name":"Acme","slug":"acme"}]}`)
	}))
	defer server.Close()

	result, err := OrganizationsList.Execute(context.Background(), api.New(server.URL, server.Client()), OrganizationsListInput{
		PageInput: PageInput{Page: 2, PageSize: 25},
	})
	if err != nil {
		t.Fatalf("execute organizations.list: %v", err)
	}
	if gotPage != "2" || gotPageSize != "25" {
		t.Fatalf("unexpected pagination query: page=%q page_size=%q", gotPage, gotPageSize)
	}
	if len(result.Results) != 1 || result.Results[0].Slug != "acme" {
		t.Fatalf("unexpected organizations: %+v", result.Results)
	}
	if result.Pagination.Page != 2 || result.Pagination.PageSize != 25 || result.Pagination.Count != 1 {
		t.Fatalf("unexpected pagination: %+v", result.Pagination)
	}
}

func TestOrganizationsListUsesDefaults(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":0,"next":null,"previous":null,"results":[]}`)
	}))
	defer server.Close()

	_, err := OrganizationsList.Execute(context.Background(), api.New(server.URL, server.Client()), OrganizationsListInput{})
	if err != nil {
		t.Fatalf("execute organizations.list: %v", err)
	}
	want := "page=1&page_size=50"
	if query != want {
		t.Fatalf("query = %q, want %q", query, want)
	}
}

func TestOrganizationsListRejectsInvalidPageSize(t *testing.T) {
	_, err := OrganizationsList.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), OrganizationsListInput{
		PageInput: PageInput{PageSize: MaxPageSize + 1},
	})
	if err == nil {
		t.Fatal("expected page_size validation error")
	}
}

func TestOrganizationsListReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"denied"}`, http.StatusForbidden)
	}))
	defer server.Close()

	_, err := OrganizationsList.Execute(context.Background(), api.New(server.URL, server.Client()), OrganizationsListInput{})
	if err == nil {
		t.Fatal("expected API error")
	}
}
