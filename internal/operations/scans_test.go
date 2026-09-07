package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fencer/cli/api"
)

func TestScansList(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":101,"slug":"SCAN-9RG","status":"completed","branch":"main"}]}`)
	}))
	defer server.Close()

	got, err := ScansList.Execute(context.Background(), api.New(server.URL, server.Client()), ScansListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		PageInput:         PageInput{Page: 2, PageSize: 25},
		Asset:             "ARES-BDA",
		Branch:            "main",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/asset-inventory/ARES-BDA/scans/" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{"page=2", "page_size=25", "branch=main"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(got.Results) != 1 || got.Results[0].Slug != "SCAN-9RG" {
		t.Fatalf("unexpected results: %+v", got.Results)
	}
}

func TestScansListRequiresAsset(t *testing.T) {
	_, err := ScansList.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), ScansListInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing asset error")
	}
}

func TestScansGet(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":101,"slug":"SCAN-9RG","status":"completed","asset_id":7,"asset_type":"repository","asset_name":"web-app","counts":{"count_new":2}}`)
	}))
	defer server.Close()

	got, err := ScansGet.Execute(context.Background(), api.New(server.URL, server.Client()), ScansGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "SCAN-9RG",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/scans/SCAN-9RG/" {
		t.Fatalf("path = %q", gotPath)
	}
	if got.Slug != "SCAN-9RG" || got.AssetType != "repository" || got.Counts.CountNew != 2 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestScansGetRequiresSlug(t *testing.T) {
	_, err := ScansGet.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), ScansGetInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing slug error")
	}
}

func TestScansListVulnerabilities(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":501,"slug":"v","title":"New finding","severity":0,"status":"open","new":true,"asset_id":7,"asset_type":"repository"}]}`)
	}))
	defer server.Close()

	newOnly := true
	got, err := ScansListVulnerabilities.Execute(context.Background(), api.New(server.URL, server.Client()), ScansListVulnerabilitiesInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		PageInput:         PageInput{Page: 2, PageSize: 25},
		Slug:              "SCAN-9RG",
		New:               &newOnly,
		Severity:          []string{"critical"},
		Query:             "finding",
		OrderBy:           "-severity",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/scans/SCAN-9RG/vulnerability-snapshots/" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{"page=2", "page_size=25", "new=true", "severity=0", "q=finding", "order_by=-severity"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(got.Results) != 1 || got.Results[0].Title != "New finding" || got.Results[0].AssetType != "repository" {
		t.Fatalf("unexpected results: %+v", got.Results)
	}
}

func TestScansListVulnerabilitiesRequiresSlug(t *testing.T) {
	_, err := ScansListVulnerabilities.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), ScansListVulnerabilitiesInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing slug error")
	}
}

func TestScansListVulnerabilitiesInvalidSeverity(t *testing.T) {
	_, err := ScansListVulnerabilities.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), ScansListVulnerabilitiesInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "SCAN-9RG",
		Severity:          []string{"nope"},
	})
	if err == nil {
		t.Fatal("expected invalid severity error")
	}
}

func TestScansDiff(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "new=true") {
			_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":501,"slug":"vuln-new","title":"New finding","severity":0,"new":true}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":400,"slug":"vuln-old","title":"Resolved finding","severity":2,"resolved":true}]}`)
	}))
	defer server.Close()

	got, err := ScansDiff.Execute(context.Background(), api.New(server.URL, server.Client()), ScansDiffInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "SCAN-9RG",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got.Slug != "SCAN-9RG" || len(got.New) != 1 || got.New[0].Slug != "vuln-new" || len(got.Resolved) != 1 || got.Resolved[0].Slug != "vuln-old" {
		t.Fatalf("unexpected diff: %+v", got)
	}
	if len(queries) != 2 {
		t.Fatalf("expected 2 requests, got %d: %v", len(queries), queries)
	}
	if !strings.Contains(queries[0], "new=true") || !strings.Contains(queries[0], "page_size=1000") {
		t.Fatalf("new query = %q", queries[0])
	}
	if !strings.Contains(queries[1], "resolved=true") {
		t.Fatalf("resolved query = %q", queries[1])
	}
}

func TestScansDiffCollectsAllPages(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query()
		if q.Get("new") == "true" {
			if q.Get("page") == "2" {
				_, _ = fmt.Fprint(w, `{"count":3,"next":null,"previous":"http://x/?page=1","results":[{"id":503,"slug":"vuln-new3","title":"Third","severity":2,"new":true}]}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"count":3,"next":"http://x/?page=2","previous":null,"results":[{"id":501,"slug":"vuln-new1","title":"First","severity":0,"new":true},{"id":502,"slug":"vuln-new2","title":"Second","severity":1,"new":true}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":400,"slug":"vuln-old","title":"Resolved finding","severity":2,"resolved":true}]}`)
	}))
	defer server.Close()

	got, err := ScansDiff.Execute(context.Background(), api.New(server.URL, server.Client()), ScansDiffInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "SCAN-9RG",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got.NewCount != 3 || len(got.New) != 3 || got.New[2].Slug != "vuln-new3" {
		t.Fatalf("expected all new findings, got %+v", got.New)
	}
	if got.ResolvedCount != 1 || len(got.Resolved) != 1 {
		t.Fatalf("unexpected resolved: %+v", got.Resolved)
	}
	newPages := 0
	for _, query := range queries {
		if strings.Contains(query, "new=true") {
			newPages++
		}
	}
	if newPages != 2 {
		t.Fatalf("expected 2 new-side requests, got %d: %v", newPages, queries)
	}
}

func TestScansDiffRequiresSlug(t *testing.T) {
	_, err := ScansDiff.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), ScansDiffInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing slug error")
	}
}

func TestScansSchedule(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"message":"Scan scheduled","scan_id":202,"slug":"SCAN-202"}`)
	}))
	defer server.Close()

	got, err := ScansSchedule.Execute(context.Background(), api.New(server.URL, server.Client()), ScansScheduleInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "ARES-AJ3",
		Branch:            "main",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/org/acme/asset-inventory/ARES-AJ3/trigger-scan/" {
		t.Fatalf("unexpected request %s %s", gotMethod, gotPath)
	}
	if gotBody["branch"] != "main" {
		t.Fatalf("body = %+v", gotBody)
	}
	if got.Slug == nil || *got.Slug != "SCAN-202" || got.Message != "Scan scheduled" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestScansScheduleOmitsBranchWhenEmpty(t *testing.T) {
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"message":"Scan scheduled"}`)
	}))
	defer server.Close()

	_, err := ScansSchedule.Execute(context.Background(), api.New(server.URL, server.Client()), ScansScheduleInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "ARES-CLD1",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if _, ok := gotBody["branch"]; ok {
		t.Fatalf("expected no branch in body, got %+v", gotBody)
	}
}

func TestScansScheduleRequiresSlug(t *testing.T) {
	_, err := ScansSchedule.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), ScansScheduleInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
	})
	if err == nil {
		t.Fatal("expected missing slug error")
	}
}
