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

func TestIdentitiesList(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":11,"slug":"OID-9C4","name":"alice","email":"alice@example.com","identity_type":"user"}]}`)
	}))
	defer server.Close()

	needsReview := true
	got, err := IdentitiesList.Execute(context.Background(), api.New(server.URL, server.Client()), IdentitiesListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		PageInput:         PageInput{Page: 2, PageSize: 25},
		Type:              "user",
		Status:            "active",
		Relationship:      "employee",
		NeedsReview:       &needsReview,
		Query:             "alice",
		OrderBy:           "display_name",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/identities/" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{
		"page=2",
		"page_size=25",
		"identity_type=user",
		"identity_status=active",
		"identity_relationship=employee",
		"needs_review=true",
		"q=alice",
		"order_by=display_name",
	} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(got.Results) != 1 || got.Results[0].Slug != "OID-9C4" || got.Results[0].Name != "alice" || got.Results[0].Email != "alice@example.com" || got.Results[0].IdentityType != "user" {
		t.Fatalf("unexpected results: %+v", got.Results)
	}
}
