package cmd

import (
	"net/http"
	"strings"
	"testing"
)

const vulnsListJSON = `{"count":0,"next":null,"previous":null,"results":[]}`

const assetInventoryConfigJSON = `{"filters":{` +
	`"kind":{"label":"Asset Kind","type":"enum","options":[` +
	`{"value":"artifact","label":"Artifact"},` +
	`{"value":"aws_ec2_instance","label":"AWS - EC2 Instance"},` +
	`{"value":"cloud_account","label":"Cloud Account"}]},` +
	`"provider":{"label":"Asset Provider","type":"enum","options":[` +
	`{"value":"aws","label":"AWS"}]}}}`

const assetsListJSON = `{"count":0,"next":null,"previous":null,"results":[]}`

const assetsListPopulatedJSON = `{"count":1,"next":null,"previous":null,"results":[` +
	`{"id":1,"slug":"AR-1","kind_name":"Cloud Account","provider_name":"AWS",` +
	`"description":"prod-account","belongs_to":"acme","asset_id":11,"asset_type":"cloud_account","criticality":50}]}`

func assetConfigServer(t *testing.T) (string, *[]recordedRequest) {
	t.Helper()
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/asset-inventory/config/":
			return 200, assetInventoryConfigJSON
		case "/api/v1/org/acme/asset-inventory/":
			return 200, assetsListJSON
		}
		return 404, `{}`
	})
	return srv.URL, recs
}

func TestAssetListTypeValid(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/asset-inventory/config/":
			return 200, assetInventoryConfigJSON
		case "/api/v1/org/acme/asset-inventory/":
			return 200, assetsListPopulatedJSON
		}
		return 404, `{}`
	})

	rootCmd.SetArgs([]string{"asset", "list", "--kind", "cloud_account", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// A valid canonical kind with results is the recon hot path: one request, config skipped.
	if len(*recs) != 1 {
		t.Fatalf("expected 1 request (list only; config skipped), got %d: %+v", len(*recs), *recs)
	}
	listReq := (*recs)[0]
	if listReq.Path != "/api/v1/org/acme/asset-inventory/" {
		t.Fatalf("expected list request, got %+v", listReq)
	}
	if !strings.Contains(listReq.Query, "cloud_account") {
		t.Errorf("expected cloud_account in list query %q", listReq.Query)
	}
}

func TestAssetListTypeValidEmptyValidates(t *testing.T) {
	setupActionTest(t)
	url, recs := assetConfigServer(t) // list returns empty

	rootCmd.SetArgs([]string{"asset", "list", "--kind", "cloud_account", "--org", "acme", "--base-url", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Empty list → config consulted to validate; kind is valid & canonical → no retry, no error.
	if len(*recs) != 2 {
		t.Fatalf("expected 2 requests (empty list + config), got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/asset-inventory/" {
		t.Errorf("expected list request first, got %+v", (*recs)[0])
	}
	if (*recs)[1].Path != "/api/v1/org/acme/asset-inventory/config/" {
		t.Errorf("expected config request second, got %+v", (*recs)[1])
	}
}

func TestVulnListRejectsOversizedPageSize(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})
	rootCmd.SetArgs([]string{"vuln", "list", "--org", "acme", "--base-url", srv.URL, "--page-size", "1001"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected page-size validation error")
	}
	if len(*recs) != 0 {
		t.Errorf("expected no request on invalid page-size, got %+v", *recs)
	}
}

func TestVulnListDefaultsToOpen(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		if r.URL.Path == "/api/v1/org/acme/vulnerabilities/" {
			return 200, vulnsListJSON
		}
		return 404, `{}`
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--org", "acme", "--base-url", srv.URL, "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	if !strings.Contains((*recs)[0].Query, "status=open") {
		t.Errorf("expected default status=open in query, got %q", (*recs)[0].Query)
	}
}

func TestVulnListStatusAllSendsNoFilter(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		if r.URL.Path == "/api/v1/org/acme/vulnerabilities/" {
			return 200, vulnsListJSON
		}
		return 404, `{}`
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--status", "all", "--org", "acme", "--base-url", srv.URL, "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if strings.Contains((*recs)[0].Query, "status=") {
		t.Errorf("expected no status filter for --status all, got %q", (*recs)[0].Query)
	}
}

func TestAssetListTypeEmptyJSONSkipsConfig(t *testing.T) {
	setupActionTest(t)
	url, recs := assetConfigServer(t) // list returns empty

	// JSON output is the pentest recon hot path: an empty result is a valid answer, so the CLI must
	// NOT fall back to the heavier config endpoint to validate/suggest the kind. This is the
	// regression guard for ENG-8769 (the config endpoint scanned the whole org inventory).
	rootCmd.SetArgs([]string{"asset", "list", "--kind", "cloud_account", "--org", "acme", "--base-url", url, "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request (list only; config skipped in json mode), got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/asset-inventory/" {
		t.Errorf("expected list request only, got %+v", (*recs)[0])
	}
}

func TestAssetListTypeInvalidJSONNoError(t *testing.T) {
	setupActionTest(t)
	url, recs := assetConfigServer(t) // list returns empty

	// An invalid/typo kind in json mode returns an empty page (no "did you mean" error, no config
	// request) — machine callers get count:0 rather than a non-zero exit.
	rootCmd.SetArgs([]string{"asset", "list", "--kind", "zzzz", "--org", "acme", "--base-url", url, "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request (list only; config skipped), got %d: %+v", len(*recs), *recs)
	}
}

func TestAssetListTypeMiscasedRetries(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/asset-inventory/config/":
			return 200, assetInventoryConfigJSON
		case "/api/v1/org/acme/asset-inventory/":
			if strings.Contains(r.URL.RawQuery, "cloud_account") {
				return 200, assetsListPopulatedJSON
			}
			return 200, assetsListJSON // empty for the mis-cased value
		}
		return 404, `{}`
	})

	rootCmd.SetArgs([]string{"asset", "list", "--kind", "CLOUD_ACCOUNT", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Empty list (mis-cased) → config canonicalizes to cloud_account → retry list = 3 requests.
	if len(*recs) != 3 {
		t.Fatalf("expected 3 requests (list, config, retried list), got %d: %+v", len(*recs), *recs)
	}
	retry := (*recs)[2]
	if retry.Path != "/api/v1/org/acme/asset-inventory/" || !strings.Contains(retry.Query, "cloud_account") {
		t.Errorf("expected retried list with canonical kind, got %+v", retry)
	}
}

func TestAssetListTypeInvalidSuggests(t *testing.T) {
	setupActionTest(t)
	url, recs := assetConfigServer(t)

	rootCmd.SetArgs([]string{"asset", "list", "--kind", "cloud", "--org", "acme", "--base-url", url})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid asset type, got nil")
	}
	if !strings.Contains(err.Error(), `Did you mean "cloud_account"`) {
		t.Errorf("expected suggestion for cloud_account, got %v", err)
	}
	// Empty list first, then config to validate & suggest.
	if len(*recs) != 2 {
		t.Fatalf("expected 2 requests (empty list + config), got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/asset-inventory/" {
		t.Errorf("expected list request first, got %+v", (*recs)[0])
	}
	if (*recs)[1].Path != "/api/v1/org/acme/asset-inventory/config/" {
		t.Errorf("expected config request second, got %+v", (*recs)[1])
	}
}

func TestAssetListTypeLabelSuggests(t *testing.T) {
	setupActionTest(t)
	url, _ := assetConfigServer(t)

	rootCmd.SetArgs([]string{"asset", "list", "--kind", "cloud account", "--org", "acme", "--base-url", url})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for human-label asset type, got nil")
	}
	if !strings.Contains(err.Error(), `Did you mean "cloud_account"`) {
		t.Errorf("expected suggestion for cloud_account, got %v", err)
	}
}

func TestAssetListTypeNoCloseMatch(t *testing.T) {
	setupActionTest(t)
	url, _ := assetConfigServer(t)

	rootCmd.SetArgs([]string{"asset", "list", "--kind", "zzzzzzzz", "--org", "acme", "--base-url", url})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown asset type, got nil")
	}
	if strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("did not expect a suggestion for an unrelated value, got %v", err)
	}
}

func TestAssetFiltersListsFields(t *testing.T) {
	setupActionTest(t)
	url, _ := assetConfigServer(t)

	rootCmd.SetArgs([]string{"asset", "filters", "--org", "acme", "--base-url", url})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	for _, want := range []string{"kind", "Asset Kind", "provider"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in fields output:\n%s", want, out)
		}
	}
}

func TestAssetFiltersListsKindValues(t *testing.T) {
	setupActionTest(t)
	url, _ := assetConfigServer(t)

	rootCmd.SetArgs([]string{"asset", "filters", "kind", "--org", "acme", "--base-url", url})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	for _, want := range []string{"cloud_account", "Cloud Account", "aws_ec2_instance"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in kind values output:\n%s", want, out)
		}
	}
}

func TestAssetFiltersUnknownField(t *testing.T) {
	setupActionTest(t)
	url, _ := assetConfigServer(t)

	rootCmd.SetArgs([]string{"asset", "filters", "bogus", "--org", "acme", "--base-url", url})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown filter field") {
		t.Errorf("expected unknown filter field error, got %v", err)
	}
}

func TestVulnListSeverityTranslation(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--severity", "critical", "--severity", "high", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*recs))
	}
	got := (*recs)[0].Query
	for _, s := range []string{"severity=0", "severity=1"} {
		if !strings.Contains(got, s) {
			t.Errorf("expected %q in query %q", s, got)
		}
	}
}

func TestVulnListSeverityInvalid(t *testing.T) {
	setupActionTest(t)
	srv, _ := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--severity", "bogus", "--org", "acme", "--base-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid severity, got nil")
	}
}

func TestVulnListAssetSlug(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--asset", "ARES-AJ3", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := (*recs)[0].Query; !strings.Contains(got, "asset=ARES-AJ3") {
		t.Errorf("expected asset=ARES-AJ3 in query %q", got)
	}
}

func TestVulnListIgnoredBoolTrue(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--ignored", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := (*recs)[0].Query; !strings.Contains(got, "ignored_by=true") {
		t.Errorf("expected ignored_by=true in query %q", got)
	}
}

func TestVulnListIgnoredBoolFalse(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--ignored=false", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := (*recs)[0].Query; !strings.Contains(got, "ignored_by=false") {
		t.Errorf("expected ignored_by=false in query %q", got)
	}
}

func TestVulnListIgnoredAbsentOmitsFilter(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := (*recs)[0].Query; strings.Contains(got, "ignored_by=") {
		t.Errorf("expected no ignored_by filter in query %q", got)
	}
}

func TestVulnListAssigneeRejectsNumeric(t *testing.T) {
	setupActionTest(t)
	srv, _ := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--assignee", "99", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for numeric --assignee, got nil")
	}
}

func TestVulnListAssigneeEmail(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/users/":
			return 200, orgUsersAliceJSON
		case "/api/v1/org/acme/vulnerabilities/":
			return 200, vulnsListJSON
		}
		return 404, `{}`
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--assignee", "alice@acme.dev", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if len(*recs) != 2 {
		t.Fatalf("expected 2 requests (lookup + list), got %d: %+v", len(*recs), *recs)
	}
	listReq := (*recs)[1]
	if !strings.Contains(listReq.Query, "assignee=99") {
		t.Errorf("expected assignee=99 in list query %q", listReq.Query)
	}
}

func TestVulnListAssigneeMe(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/me/":
			return 200, currentUserJSON
		case "/api/v1/org/acme/vulnerabilities/":
			return 200, vulnsListJSON
		}
		return 404, `{}`
	})

	rootCmd.SetArgs([]string{"vuln", "list", "--assignee", "me", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	listReq := (*recs)[len(*recs)-1]
	if !strings.Contains(listReq.Query, "assignee=77") {
		t.Errorf("expected assignee=77 in list query %q", listReq.Query)
	}
}

func TestDetectionListSeverityTranslation(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"detection", "list", "--severity", "medium", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := (*recs)[0].Query; !strings.Contains(got, "severity=2") {
		t.Errorf("expected severity=2 in query %q", got)
	}
}

func TestScanVulnsSeverityTranslation(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{"scan", "vulns", "101", "--severity", "low", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if got := (*recs)[0].Query; !strings.Contains(got, "severity=3") {
		t.Errorf("expected severity=3 in query %q", got)
	}
}

func TestIdentityListFilters(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, vulnsListJSON
	})

	rootCmd.SetArgs([]string{
		"identity", "list",
		"--type", "user",
		"--needs-review",
		"--org", "acme",
		"--base-url", srv.URL,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := (*recs)[0].Query
	if !strings.Contains(got, "identity_type=user") {
		t.Errorf("expected identity_type=user in query %q", got)
	}
	if !strings.Contains(got, "needs_review=true") {
		t.Errorf("expected needs_review=true in query %q", got)
	}
}
