package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fencer/cli/api"
)

// newMCPSession wires the read-only tool set onto an in-memory MCP server backed
// by a recording HTTP server, and returns a connected client session plus the
// recorded requests.
func newMCPSession(t *testing.T, respond func(r *http.Request) (int, string)) (*mcp.ClientSession, *[]recordedRequest) {
	t.Helper()
	srv, recs := newRecordingServer(t, respond)
	client := api.New(srv.URL, srv.Client())

	server := mcp.NewServer(&mcp.Implementation{Name: "fencer", Version: "test"}, nil)
	registerMCPTools(server, client)

	serverT, clientT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, recs
}

// callTool invokes a tool and fails the test on transport-level errors.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return res
}

func toolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

const okListJSON = `{"count":0,"next":null,"previous":null,"results":[]}`

func TestMCPListsAllReadOnlyTools(t *testing.T) {
	setupActionTest(t)
	cs, _ := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	got, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range got.Tools {
		names[tool.Name] = true
	}
	want := []string{
		"organizations.list", "vulnerabilities.list", "vulnerabilities.get",
		"assets.list", "assets.get", "scans.list", "detections.list", "detections.get",
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("missing tool %q; got %v", w, names)
		}
	}
}

func TestMCPOrganizationsListPath(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) {
		return 200, `{"count":1,"next":null,"previous":null,"results":[{"id":7,"name":"Acme","slug":"acme"}]}`
	})

	result := callTool(t, cs, "organizations.list", map[string]any{"page": 2, "page_size": 25})

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/organizations/api/organizations/" {
		t.Errorf("unexpected path %q", (*recs)[0].Path)
	}
	if (*recs)[0].Query != "page=2&page_size=25" {
		t.Errorf("unexpected query %q", (*recs)[0].Query)
	}
	if result.StructuredContent == nil {
		t.Fatal("expected structured organizations.list output")
	}
	structured, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	for _, field := range []string{`"results"`, `"pagination"`, `"slug":"acme"`, `"page":2`, `"page_size":25`} {
		if !strings.Contains(string(structured), field) {
			t.Errorf("structured content missing %s: %s", field, structured)
		}
	}
	if strings.Contains(string(structured), `"id":`) {
		t.Errorf("structured content leaked internal id: %s", structured)
	}
}

func TestMCPOrganizationsListHasTypedSchemas(t *testing.T) {
	setupActionTest(t)
	cs, _ := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range tools.Tools {
		if tool.Name != "organizations.list" {
			continue
		}
		input, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal input schema: %v", err)
		}
		output, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("marshal output schema: %v", err)
		}
		for _, field := range []string{"page", "page_size"} {
			if !strings.Contains(string(input), `"`+field+`"`) {
				t.Errorf("input schema missing %q: %s", field, input)
			}
		}
		for _, field := range []string{"results", "pagination"} {
			if !strings.Contains(string(output), `"`+field+`"`) {
				t.Errorf("output schema missing %q: %s", field, output)
			}
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || !tool.Annotations.IdempotentHint {
			t.Errorf("unexpected annotations: %+v", tool.Annotations)
		}
		return
	}
	t.Fatal("organizations.list tool not found")
}

func TestOrgListCommandReferencesSharedOperation(t *testing.T) {
	if got := orgListCmd.Annotations[operationAnnotation]; got != "organizations.list" {
		t.Fatalf("org list operation annotation = %q, want organizations.list", got)
	}
}

func TestMCPVulnerabilitiesListHasTypedSchemas(t *testing.T) {
	setupActionTest(t)
	cs, _ := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range tools.Tools {
		if tool.Name != "vulnerabilities.list" {
			continue
		}
		input, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal input schema: %v", err)
		}
		output, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("marshal output schema: %v", err)
		}
		for _, field := range []string{"organization_slug", "severity", "page", "page_size", "order_by", "first_seen", "-first_seen"} {
			if !strings.Contains(string(input), `"`+field+`"`) {
				t.Errorf("input schema missing %q: %s", field, input)
			}
		}
		for _, field := range []string{"results", "pagination"} {
			if !strings.Contains(string(output), `"`+field+`"`) {
				t.Errorf("output schema missing %q: %s", field, output)
			}
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || !tool.Annotations.IdempotentHint {
			t.Errorf("unexpected annotations: %+v", tool.Annotations)
		}
		return
	}
	t.Fatal("vulnerabilities.list tool not found")
}

func TestMCPListOrderByUsesGeneratedEnums(t *testing.T) {
	setupActionTest(t)
	cs, _ := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	cases := map[string][]string{
		"vulnerabilities.list":       {"order_by", "first_seen", "-first_seen", "ai-agent"},
		"detections.list":            {"order_by", "detected_at", "-detected_at", "confidence_label"},
		"identities.list":            {"order_by", "display_name", "-display_name", "last_seen_at", "-last_seen_at"},
		"assets.list":                {"order_by", "kind", "-kind"},
		"scans.list_vulnerabilities": {"order_by", "first_seen", "-first_seen", "ai-agent"},
	}
	seen := map[string]bool{}
	for _, tool := range tools.Tools {
		want, ok := cases[tool.Name]
		if !ok {
			continue
		}
		input, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal input schema: %v", err)
		}
		for _, field := range want {
			if !strings.Contains(string(input), `"`+field+`"`) {
				t.Errorf("%s input schema missing %q: %s", tool.Name, field, input)
			}
		}
		seen[tool.Name] = true
	}
	for name := range cases {
		if !seen[name] {
			t.Errorf("tool %s not found", name)
		}
	}
}

func TestMCPVulnerabilitiesListBuildsQuery(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	callTool(t, cs, "vulnerabilities.list", map[string]any{
		"organization_slug": "acme",
		"asset":             []string{"ARES-BDA", "ARES-AJ3"},
		"status":            "open",
		"severity":          []string{"critical", "high"},
		"has_assignee":      false,
		"page":              2,
		"page_size":         50,
	})

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	rec := (*recs)[0]
	if rec.Path != "/api/v1/org/acme/vulnerabilities/" {
		t.Errorf("unexpected path %q", rec.Path)
	}
	for _, want := range []string{
		"asset=ARES-BDA", "asset=ARES-AJ3", "status=open",
		"severity=0", "severity=1", "has_assignee=false", "page=2", "page_size=50",
	} {
		if !strings.Contains(rec.Query, want) {
			t.Errorf("query %q missing %q", rec.Query, want)
		}
	}
}

func TestMCPVulnerabilitiesListInvalidSeverityIsToolError(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	res := callTool(t, cs, "vulnerabilities.list", map[string]any{
		"organization_slug": "acme",
		"severity":          []string{"nope"},
	})

	if !res.IsError {
		t.Fatalf("expected tool error for invalid severity, got %q", toolText(t, res))
	}
	if len(*recs) != 0 {
		t.Errorf("expected no request on validation failure, got %+v", *recs)
	}
}

func TestMCPVulnerabilityGetHasTypedSchemas(t *testing.T) {
	setupActionTest(t)
	cs, _ := newMCPSession(t, func(*http.Request) (int, string) { return 200, `{"slug":"vuln-abc"}` })

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range tools.Tools {
		if tool.Name != "vulnerabilities.get" {
			continue
		}
		input, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal input schema: %v", err)
		}
		output, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("marshal output schema: %v", err)
		}
		if !strings.Contains(string(input), `"slug"`) {
			t.Errorf("input schema missing slug: %s", input)
		}
		if !strings.Contains(string(output), `"title"`) {
			t.Errorf("output schema missing title: %s", output)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("unexpected annotations: %+v", tool.Annotations)
		}
		return
	}
	t.Fatal("vulnerabilities.get tool not found")
}

func TestMCPVulnerabilityGetPath(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, `{"slug":"vuln-abc"}` })

	callTool(t, cs, "vulnerabilities.get", map[string]any{"organization_slug": "acme", "slug": "vuln-abc"})

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*recs))
	}
	if (*recs)[0].Path != "/api/v1/org/acme/vulnerabilities/vuln-abc/" {
		t.Errorf("unexpected path %q", (*recs)[0].Path)
	}
}

func TestMCPAssetToolsPaths(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	callTool(t, cs, "assets.list", map[string]any{"organization_slug": "acme", "search": "web", "top_level": true})
	callTool(t, cs, "assets.get", map[string]any{"organization_slug": "acme", "slug": "ARES-BDA"})
	callTool(t, cs, "scans.list", map[string]any{"organization_slug": "acme", "asset": "ARES-BDA", "branch": "main"})

	if len(*recs) != 3 {
		t.Fatalf("expected 3 requests, got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/asset-inventory/" || !strings.Contains((*recs)[0].Query, "top_level=true") {
		t.Errorf("assets.list unexpected: %+v", (*recs)[0])
	}
	if (*recs)[1].Path != "/api/v1/org/acme/asset-inventory/ARES-BDA/" {
		t.Errorf("assets.get unexpected path %q", (*recs)[1].Path)
	}
	if (*recs)[2].Path != "/api/v1/org/acme/asset-inventory/ARES-BDA/scans/" || !strings.Contains((*recs)[2].Query, "branch=main") {
		t.Errorf("scans.list unexpected: %+v", (*recs)[2])
	}
}

func TestMCPScansListVulnerabilitiesPath(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	callTool(t, cs, "scans.list_vulnerabilities", map[string]any{
		"organization_slug": "acme",
		"slug":              "SCAN-9RG",
		"new":               true,
		"severity":          []string{"low"},
	})

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/scans/SCAN-9RG/vulnerability-snapshots/" {
		t.Errorf("unexpected path %q", (*recs)[0].Path)
	}
	if !strings.Contains((*recs)[0].Query, "new=true") || !strings.Contains((*recs)[0].Query, "severity=3") {
		t.Errorf("unexpected query %q", (*recs)[0].Query)
	}
}

func TestMCPScansDiffPaths(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	callTool(t, cs, "scans.diff", map[string]any{"organization_slug": "acme", "slug": "SCAN-9RG"})

	if len(*recs) != 2 {
		t.Fatalf("expected 2 requests, got %d: %+v", len(*recs), *recs)
	}
	for _, rec := range *recs {
		if rec.Path != "/api/v1/org/acme/scans/SCAN-9RG/vulnerability-snapshots/" {
			t.Errorf("unexpected path %q", rec.Path)
		}
	}
	if !strings.Contains((*recs)[0].Query, "new=true") {
		t.Errorf("first query missing new=true: %q", (*recs)[0].Query)
	}
	if !strings.Contains((*recs)[1].Query, "resolved=true") {
		t.Errorf("second query missing resolved=true: %q", (*recs)[1].Query)
	}
}

func TestMCPScansSchedulePosts(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) {
		return 200, `{"message":"Scan scheduled","scan_id":202,"slug":"SCAN-202"}`
	})

	res := callTool(t, cs, "scans.schedule", map[string]any{
		"organization_slug": "acme",
		"slug":              "ARES-AJ3",
		"branch":            "main",
	})
	if res.IsError {
		t.Fatalf("schedule tool error: %s", toolText(t, res))
	}
	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	got := (*recs)[0]
	if got.Method != "POST" || got.Path != "/api/v1/org/acme/asset-inventory/ARES-AJ3/trigger-scan/" {
		t.Errorf("unexpected request: %+v", got)
	}
	if got.Body["branch"] != "main" {
		t.Errorf("expected branch=main, got %v", got.Body)
	}
	structured, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if strings.Contains(string(structured), `"scan_id"`) || strings.Contains(string(structured), `"id":`) {
		t.Errorf("structured content leaked internal id: %s", structured)
	}
	if !strings.Contains(string(structured), `"slug":"SCAN-202"`) {
		t.Errorf("structured content missing scan slug: %s", structured)
	}
}

func TestMCPIdentitiesListPath(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	callTool(t, cs, "identities.list", map[string]any{
		"organization_slug": "acme",
		"identity_type":     "user",
		"needs_review":      true,
	})

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/identities/" {
		t.Errorf("unexpected path %q", (*recs)[0].Path)
	}
	if !strings.Contains((*recs)[0].Query, "identity_type=user") || !strings.Contains((*recs)[0].Query, "needs_review=true") {
		t.Errorf("unexpected query %q", (*recs)[0].Query)
	}
}

func TestMCPDetectionToolsPaths(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	callTool(t, cs, "detections.list", map[string]any{"organization_slug": "acme", "severity": []string{"high"}})
	callTool(t, cs, "detections.get", map[string]any{"organization_slug": "acme", "slug": "DET-9C4"})

	if len(*recs) != 2 {
		t.Fatalf("expected 2 requests, got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/detections/" || !strings.Contains((*recs)[0].Query, "severity=1") {
		t.Errorf("detections.list unexpected: %+v", (*recs)[0])
	}
	if (*recs)[1].Path != "/api/v1/org/acme/detections/DET-9C4/" {
		t.Errorf("detections.get unexpected path %q", (*recs)[1].Path)
	}
}

func TestMCPVulnerabilitiesAssignPostsUserID(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/users/":
			return 200, orgUsersAliceJSON
		case "/api/v1/org/acme/vulnerabilities/vuln-abc/assign/":
			return 200, assignedVulnJSON
		}
		return 404, `{}`
	})

	res := callTool(t, cs, "vulnerabilities.assign", map[string]any{
		"organization_slug": "acme",
		"slug":              "vuln-abc",
		"email":             "alice@acme.dev",
	})
	if res.IsError {
		t.Fatalf("assign tool error: %s", toolText(t, res))
	}
	if len(*recs) != 2 {
		t.Fatalf("expected lookup + assign, got %d: %+v", len(*recs), *recs)
	}
	assign := (*recs)[1]
	if assign.Method != "POST" || assign.Path != "/api/v1/org/acme/vulnerabilities/vuln-abc/assign/" {
		t.Errorf("unexpected assign request: %+v", assign)
	}
	if got := assign.Body["user_id"]; got != float64(99) {
		t.Errorf("expected user_id=99, got %v", got)
	}
}

func TestMCPMissingOrgIsToolError(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })

	res := callTool(t, cs, "vulnerabilities.list", map[string]any{})

	if !res.IsError {
		t.Fatalf("expected tool error when org unresolved, got %q", toolText(t, res))
	}
	if len(*recs) != 1 {
		t.Fatalf("expected organizations.list probe, got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/organizations/api/organizations/" {
		t.Errorf("unexpected path %q", (*recs)[0].Path)
	}
}

func TestMCPResolvesSoleOrganizationWhenSlugOmitted(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(r *http.Request) (int, string) {
		if r.URL.Path == "/organizations/api/organizations/" {
			return 200, `{"count":1,"next":null,"previous":null,"results":[{"id":7,"name":"Acme","slug":"acme"}]}`
		}
		return 200, okListJSON
	})

	vulns := callTool(t, cs, "vulnerabilities.list", map[string]any{})
	if vulns.IsError {
		t.Fatalf("vulnerabilities.list: %s", toolText(t, vulns))
	}
	assets := callTool(t, cs, "assets.list", map[string]any{})
	if assets.IsError {
		t.Fatalf("assets.list: %s", toolText(t, assets))
	}
	detections := callTool(t, cs, "detections.list", map[string]any{})
	if detections.IsError {
		t.Fatalf("detections.list: %s", toolText(t, detections))
	}

	if len(*recs) != 6 {
		t.Fatalf("expected 3 org probes + 3 tool calls, got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[1].Path != "/api/v1/org/acme/vulnerabilities/" {
		t.Errorf("vulnerabilities.list unexpected path %q", (*recs)[1].Path)
	}
	if (*recs)[3].Path != "/api/v1/org/acme/asset-inventory/" {
		t.Errorf("assets.list unexpected path %q", (*recs)[3].Path)
	}
	if (*recs)[5].Path != "/api/v1/org/acme/detections/" {
		t.Errorf("detections.list unexpected path %q", (*recs)[5].Path)
	}
}

func TestMCPDoesNotGuessOrganizationWhenSeveralAreAccessible(t *testing.T) {
	setupActionTest(t)
	cs, recs := newMCPSession(t, func(*http.Request) (int, string) {
		return 200, `{"count":2,"next":null,"previous":null,"results":[{"slug":"acme"},{"slug":"other"}]}`
	})

	res := callTool(t, cs, "vulnerabilities.list", map[string]any{})

	if !res.IsError {
		t.Fatalf("expected tool error when several orgs are accessible, got %q", toolText(t, res))
	}
	if len(*recs) != 1 {
		t.Fatalf("expected organizations.list probe only, got %d: %+v", len(*recs), *recs)
	}
}
