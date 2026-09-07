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

func TestDetectionsAssign(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var gotPath, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/org/acme/users/":
			_, _ = fmt.Fprint(w, `{"count":1,"next":null,"previous":null,"results":[{"id":99,"name":"Alice","email":"alice@acme.dev"}]}`)
		case "/api/v1/org/acme/detections/DET-9C4/assign/":
			gotPath = r.URL.Path
			body, _ := io.ReadAll(r.Body)
			gotBody = string(body)
			_, _ = fmt.Fprint(w, `{"id":55,"slug":"DET-9C4","title":"Suspicious login","severity":1,"status":"new","assignee_email":"alice@acme.dev"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got, err := DetectionsAssign.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsAssignInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
		Email:             "alice@acme.dev",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/detections/DET-9C4/assign/" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, `"user_id":99`) {
		t.Fatalf("body = %q", gotBody)
	}
	if got.Slug != "DET-9C4" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestDetectionsUnassign(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `{"id":55,"title":"Suspicious login","severity":1,"status":"new","assignee_email":"alice@acme.dev"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"id":55,"title":"Suspicious login","severity":1,"status":"new"}`)
	}))
	defer server.Close()

	got, err := DetectionsUnassign.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsUnassignInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got.AlreadyUnassigned || got.PreviousAssignee != "alice@acme.dev" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestDetectionsUnassignAlreadyUnassigned(t *testing.T) {
	var posts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":55,"title":"Suspicious login","severity":1,"status":"new"}`)
	}))
	defer server.Close()

	got, err := DetectionsUnassign.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsUnassignInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !got.AlreadyUnassigned {
		t.Fatal("expected already unassigned")
	}
	if posts != 0 {
		t.Fatalf("expected no POST, got %d", posts)
	}
}

func TestDetectionsInvestigate(t *testing.T) {
	var gotPath, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":55,"title":"Suspicious login","severity":1,"status":"under_investigation"}`)
	}))
	defer server.Close()

	got, err := DetectionsInvestigate.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsInvestigateInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v1/org/acme/detections/DET-9C4/transition/" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, `"status":"under_investigation"`) {
		t.Fatalf("body = %q", gotBody)
	}
	if got.Status != "under_investigation" {
		t.Fatalf("status = %q", got.Status)
	}
}

func TestDetectionsResolve(t *testing.T) {
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":55,"title":"Suspicious login","severity":1,"status":"resolved_false_positive"}`)
	}))
	defer server.Close()

	got, err := DetectionsResolve.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsResolveInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
		As:                "false-positive",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotBody, `"status":"resolved_false_positive"`) {
		t.Fatalf("body = %q", gotBody)
	}
	if got.Status != "resolved_false_positive" {
		t.Fatalf("status = %q", got.Status)
	}
}

func TestDetectionsResolveInvalidAs(t *testing.T) {
	_, err := DetectionsResolve.Execute(context.Background(), api.New("http://example.invalid", http.DefaultClient), DetectionsResolveInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
		As:                "maybe",
	})
	if err == nil {
		t.Fatal("expected invalid as error")
	}
}

func TestDetectionsReopen(t *testing.T) {
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":55,"title":"Suspicious login","severity":1,"status":"new"}`)
	}))
	defer server.Close()

	got, err := DetectionsReopen.Execute(context.Background(), api.New(server.URL, server.Client()), DetectionsReopenInput{
		OrganizationInput: OrganizationInput{OrganizationSlug: "acme"},
		Slug:              "DET-9C4",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotBody, `"status":"new"`) {
		t.Fatalf("body = %q", gotBody)
	}
	if got.Status != "new" {
		t.Fatalf("status = %q", got.Status)
	}
}
