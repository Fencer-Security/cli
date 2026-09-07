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

func TestDetectionsList(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":55,"slug":"DET-9C4","title":"Suspicious login","severity":1,"status":"new"}]}`)
	}))
	defer server.Close()

	unassigned := false
	result, err := DetectionsList.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		PageInput:         PageInput{Page: 2, PageSize: 25},
		Asset:             []string{"ARES-AJ3"},
		Severity:          []string{"high"},
		HasAssignee:       &unassigned,
		DetectedAt:        "7d",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/detections/" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{"page=2", "page_size=25", "asset=ARES-AJ3", "severity=1", "has_assignee=false", "detected_at=7d"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(result.Results) != 1 || result.Results[0].Slug != "DET-9C4" {
		t.Fatalf("unexpected results: %+v", result.Results)
	}
}

func TestDetectionsListInvalidSeverity(t *testing.T) {
	_, err := DetectionsList.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), DetectionsListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Severity:          []string{"nope"},
	})
	if err == nil {
		t.Fatal("expected invalid severity error")
	}
}

func TestDetectionsGet(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":55,"slug":"DET-9C4","title":"Suspicious login","severity":1,"status":"new"}`)
	}))
	defer server.Close()

	got, err := DetectionsGet.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/detections/DET-9C4/" {
		t.Fatalf("path = %q", gotPath)
	}
	if got.Slug != "DET-9C4" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestDetectionsGetRequiresSlug(t *testing.T) {
	_, err := DetectionsGet.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), DetectionsGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing slug error")
	}
}
