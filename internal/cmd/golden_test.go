package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// resetState resets package-level globals and swaps in an unauthenticated HTTP client.
// The original newHTTPClient is restored via t.Cleanup.

var update = flag.Bool("update", false, "regenerate golden files")

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[mGKHF]`)

func TestMain(m *testing.M) {
	_ = os.Setenv("NO_COLOR", "1")
	flag.Parse()
	os.Exit(m.Run())
}

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return ansiRe.ReplaceAllString(string(out), "")
}

func resetState(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	outputFormat = "table"
	orgSlug = ""
	baseURLFlag = ""
	pageFlag = 1
	pageSizeFlag = defaultPageSize
	assetKind = ""
	assetOrderBy = ""
	assetTopLevel = false
	vulnSeverity = nil
	vulnStatus = ""
	vulnCategory = ""
	vulnAsset = nil
	vulnAssignee = nil
	vulnQuery = ""
	vulnLive.reset()
	vulnIgnored.reset()
	vulnDeferred.reset()
	vulnHasAssignee.reset()
	vulnPriority = nil
	vulnInScope.reset()
	vulnOrderBy = ""
	detectionSeverity = nil
	detectionStatus = ""
	detectionAsset = nil
	detectionAssignee = nil
	detectionHasAssignee.reset()
	detectionQuery = ""
	detectionDetectedAt = ""
	detectionOrderBy = ""
	identityType = ""
	identityStatus = ""
	identityRelationship = ""
	identityNeedsReview.reset()
	identityHasOwner.reset()
	identityQuery = ""
	identityOrderBy = ""
	scanListAsset = ""
	scanListBranch = ""
	scanVulnsNew.reset()
	scanVulnsResolved.reset()
	scanVulnsIgnored.reset()
	scanVulnsSeverity = nil
	scanVulnsStatus = ""
	scanVulnsCategory = ""
	scanVulnsQuery = ""
	scanVulnsOrderBy = ""
	yesFlag = false
	vulnAssignEmail = ""
	vulnAssignMe = false
	vulnIgnoreReason = ""
	vulnIgnoreNotes = ""
	vulnDeferDays = 7
	vulnDeferReason = ""
	vulnDeferNotes = ""
	vulnPriorityLevel = ""
	assetCriticalityScore = 0
	detectionAssignEmail = ""
	detectionAssignMe = false
	detectionResolveAs = ""
	orig := newHTTPClient
	newHTTPClient = func(string) *http.Client { return &http.Client{} }
	t.Cleanup(func() { newHTTPClient = orig })
}

func routeHandler(routes map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := routes[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, body)
			return
		}
		http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
	})
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	golden := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("golden file missing — run: go test ./internal/cmd/ -update\n%v", err)
	}
	if got != string(want) {
		t.Errorf("output mismatch for %s\n\ngot:\n%s\nwant:\n%s", name, got, string(want))
	}
}

const (
	orgsJSON   = `{"count":2,"next":null,"previous":null,"results":[{"id":1,"name":"Acme Corp","slug":"acme"},{"id":2,"name":"Beta Inc","slug":"beta"}]}`
	vulnsJSON  = `{"count":1,"next":null,"previous":null,"results":[{"id":42,"slug":"vuln-abc123","title":"SQL Injection in login form","severity":1,"status":"open","asset_id":7,"asset_type":"repository","asset_name":"web-app","asset_resource_slug":"ARES-AJ3","asset_resource_kind":"repository","assignee_id":11,"assignee_email":"alice@example.com","assignee_name":"Alice Smith","web_url":"https://app.fencer.dev/a/acme/vulnerabilities/vuln-abc123/"}]}`
	vulnJSON   = `{"id":42,"slug":"vuln-abc123","title":"SQL Injection in login form","severity":1,"status":"open","asset_id":7,"asset_type":"repository","asset_name":"web-app","asset_resource_slug":"ARES-AJ3","asset_resource_kind":"repository","assignee_id":11,"assignee_email":"alice@example.com","assignee_name":"Alice Smith","web_url":"https://app.fencer.dev/a/acme/vulnerabilities/vuln-abc123/"}`
	assetsJSON = `{"count":2,"next":null,"previous":null,"results":[{"id":1,"slug":"AR-9R4","kind_name":"Application","provider_name":"Azure","category":"web","description":"checkout-service","belongs_to":"acme","asset_id":11,"asset_type":"application","criticality":80},{"id":2,"slug":"AR-K2X","kind_name":"Repository","provider_name":"GitHub","category":"code","description":"acme-corp/web","belongs_to":"acme","asset_id":22,"asset_type":"repository","criticality":50}]}`
	assetJSON  = `{"id":1,"slug":"AR-9R4","kind_name":"Application","provider_name":"Azure","category":"web","description":"checkout-service","belongs_to":"acme","asset_id":11,"asset_type":"application","criticality":80}`
	// Multi-page fixture: 120 total, page 1 of 3 at page_size=50.
	vulnsPagedJSON = `{"count":120,"next":"http://x/?page=2","previous":null,"results":[{"id":1,"slug":"v1","title":"A","severity":1,"status":"open","asset_id":1,"asset_type":"repository","asset_name":"a","asset_resource_slug":"ARES-X1","asset_resource_kind":"repository","web_url":"u1"}]}`
	// Scan history fixtures
	scansJSON             = `{"count":2,"next":null,"previous":null,"results":[{"id":101,"slug":"SCAN-9RG","status":"completed","created_at":"2026-04-20T10:00:00Z","trigger_type":"manual","trigger_by_name":"Alice","branch":"main","count_vulnerabilities":5,"count_new":2,"count_critical":1,"count_high":1},{"id":100,"slug":"SCAN-9RF","status":"failed","created_at":"2026-04-19T09:00:00Z","trigger_type":"scheduled","branch":"main","failed_reason":"timeout"}]}`
	scanDetailJSON        = `{"id":101,"slug":"SCAN-9RG","status":"completed","queued_at":"2026-04-20T09:59:00Z","started_at":"2026-04-20T10:00:00Z","finished_at":"2026-04-20T10:05:30Z","duration_seconds":330.5,"asset_id":7,"asset_type":"repository","asset_name":"web-app","branch":"main","trigger_type":"manual","trigger_description":"Manual scan by Alice","counts":{"count_new":2,"count_existing":3,"count_open":5,"count_resolved":0,"count_ignored":0,"count_critical_high":2}}`
	scanVulnsJSON         = `{"count":3,"next":null,"previous":null,"results":[{"id":501,"slug":"vuln-new1","title":"Hardcoded secret","description":"AWS access key committed to config/settings.py.","severity":0,"category":"secrets","status":"open","display_status":"new","new":true,"resolved":false,"ignored":false,"live":true,"asset_id":7,"asset_type":"repository","asset_name":"web-app","location_title":"config/settings.py:42","first_seen":"2026-04-20T10:00:00Z"},{"id":502,"slug":"vuln-new2","title":"SQL Injection","description":"Login form concatenates user input into a raw SQL query.","severity":1,"category":"injection","status":"open","display_status":"new","new":true,"resolved":false,"ignored":false,"live":true,"asset_id":7,"asset_type":"repository","asset_name":"web-app","location_title":"views/login.py:88","first_seen":"2026-04-20T10:00:00Z"},{"id":400,"slug":"vuln-old","title":"Weak TLS","description":"Server accepts TLS 1.0 connections.","severity":2,"category":"crypto","status":"open","display_status":"existing","new":false,"resolved":false,"ignored":false,"live":true,"asset_id":7,"asset_type":"repository","asset_name":"web-app","location_title":"nginx.conf:12","first_seen":"2026-03-01T10:00:00Z"}]}`
	scanVulnsNewJSON      = `{"count":2,"next":null,"previous":null,"results":[{"id":501,"slug":"vuln-new1","title":"Hardcoded secret","description":"AWS access key committed to config/settings.py.","severity":0,"category":"secrets","status":"open","display_status":"new","new":true,"resolved":false,"ignored":false,"live":true,"asset_id":7,"asset_type":"repository","asset_name":"web-app","location_title":"config/settings.py:42","first_seen":"2026-04-20T10:00:00Z"},{"id":502,"slug":"vuln-new2","title":"SQL Injection","description":"Login form concatenates user input into a raw SQL query.","severity":1,"category":"injection","status":"open","display_status":"new","new":true,"resolved":false,"ignored":false,"live":true,"asset_id":7,"asset_type":"repository","asset_name":"web-app","location_title":"views/login.py:88","first_seen":"2026-04-20T10:00:00Z"}]}`
	scanVulnsResolvedJSON = `{"count":1,"next":null,"previous":null,"results":[{"id":400,"slug":"vuln-old","title":"Weak TLS","description":"Server accepts TLS 1.0 connections.","severity":2,"category":"crypto","status":"resolved","display_status":"resolved","new":false,"resolved":true,"ignored":false,"live":false,"asset_id":7,"asset_type":"repository","asset_name":"web-app","location_title":"nginx.conf:12","first_seen":"2026-03-01T10:00:00Z"}]}`
	detectionsJSON        = `{"count":1,"next":null,"previous":null,"results":[{"id":55,"slug":"DET-9C4","title":"Suspicious login","severity":1,"status":"new","assignee_email":"alice@example.com","assignee_name":"Alice"}]}`
	identitiesJSON        = `{"count":1,"next":null,"previous":null,"results":[{"id":11,"slug":"OID-9C4","name":"alice","email":"alice@example.com","identity_type":"user"}]}`
)

func TestGolden(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		routes map[string]string
	}{
		{
			name:   "org-list-table",
			args:   []string{"org", "list"},
			routes: map[string]string{"/organizations/api/organizations/": orgsJSON},
		},
		{
			name:   "org-list-json",
			args:   []string{"org", "list", "--output", "json"},
			routes: map[string]string{"/organizations/api/organizations/": orgsJSON},
		},
		{
			name:   "vuln-list-table",
			args:   []string{"vuln", "list", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/vulnerabilities/": vulnsJSON},
		},
		{
			name:   "vuln-list-json",
			args:   []string{"vuln", "list", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/vulnerabilities/": vulnsJSON},
		},
		{
			name:   "vuln-get-table",
			args:   []string{"vuln", "get", "vuln-abc123", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/vulnerabilities/vuln-abc123/": vulnJSON},
		},
		{
			name:   "vuln-get-json",
			args:   []string{"vuln", "get", "vuln-abc123", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/vulnerabilities/vuln-abc123/": vulnJSON},
		},
		{
			name:   "asset-list-table",
			args:   []string{"asset", "list", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/asset-inventory/": assetsJSON},
		},
		{
			name:   "asset-get-table",
			args:   []string{"asset", "get", "AR-9R4", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/asset-inventory/AR-9R4/": assetJSON},
		},
		{
			name:   "asset-get-json",
			args:   []string{"asset", "get", "AR-9R4", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/asset-inventory/AR-9R4/": assetJSON},
		},
		{
			name:   "vuln-list-table-paged",
			args:   []string{"vuln", "list", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/vulnerabilities/": vulnsPagedJSON},
		},
		{
			name:   "vuln-list-json-paged",
			args:   []string{"vuln", "list", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/vulnerabilities/": vulnsPagedJSON},
		},
		{
			name:   "scan-list-table",
			args:   []string{"scan", "list", "--asset", "ARES-AJ3", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/asset-inventory/ARES-AJ3/scans/": scansJSON},
		},
		{
			name:   "scan-list-json",
			args:   []string{"scan", "list", "--asset", "ARES-AJ3", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/asset-inventory/ARES-AJ3/scans/": scansJSON},
		},
		{
			name:   "scan-get-table",
			args:   []string{"scan", "get", "SCAN-9RG", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/scans/SCAN-9RG/": scanDetailJSON},
		},
		{
			name:   "scan-get-json",
			args:   []string{"scan", "get", "SCAN-9RG", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/scans/SCAN-9RG/": scanDetailJSON},
		},
		{
			name:   "scan-vulns-table",
			args:   []string{"scan", "vulns", "SCAN-9RG", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/scans/SCAN-9RG/vulnerability-snapshots/": scanVulnsJSON},
		},
		{
			name:   "scan-vulns-json",
			args:   []string{"scan", "vulns", "SCAN-9RG", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/scans/SCAN-9RG/vulnerability-snapshots/": scanVulnsJSON},
		},
		{
			name:   "asset-list-json",
			args:   []string{"asset", "list", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/asset-inventory/": assetsJSON},
		},
		{
			name:   "detection-list-table",
			args:   []string{"detection", "list", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/detections/": detectionsJSON},
		},
		{
			name:   "detection-list-json",
			args:   []string{"detection", "list", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/detections/": detectionsJSON},
		},
		{
			name:   "identity-list-table",
			args:   []string{"identity", "list", "--org", "acme"},
			routes: map[string]string{"/api/v1/org/acme/identities/": identitiesJSON},
		},
		{
			name:   "identity-list-json",
			args:   []string{"identity", "list", "--org", "acme", "--output", "json"},
			routes: map[string]string{"/api/v1/org/acme/identities/": identitiesJSON},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(routeHandler(tt.routes))
			defer srv.Close()

			resetState(t)
			rootCmd.SetArgs(append(tt.args, "--base-url", srv.URL))
			out := captureStdout(func() { _ = rootCmd.Execute() })

			checkGolden(t, tt.name, out)
		})
	}
}

func TestGoldenJSONIsValid(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("testdata", "golden", "*-json*.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("expected json golden files")
	}
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(raw) {
			t.Errorf("%s is not valid JSON", path)
		}
	}
}

func scanVulnsQueryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query()
		switch {
		case q.Get("new") == "true":
			_, _ = fmt.Fprint(w, scanVulnsNewJSON)
		case q.Get("resolved") == "true":
			_, _ = fmt.Fprint(w, scanVulnsResolvedJSON)
		default:
			_, _ = fmt.Fprint(w, scanVulnsJSON)
		}
	})
}

func TestScanDiff(t *testing.T) {
	for _, format := range []string{"table", "json"} {
		t.Run("scan-diff-"+format, func(t *testing.T) {
			srv := httptest.NewServer(scanVulnsQueryHandler())
			defer srv.Close()

			resetState(t)
			args := []string{"scan", "diff", "SCAN-9RG", "--org", "acme", "--base-url", srv.URL}
			if format == "json" {
				args = append(args, "--output", "json")
			}
			rootCmd.SetArgs(args)
			out := captureStdout(func() { _ = rootCmd.Execute() })

			checkGolden(t, "scan-diff-"+format, out)
		})
	}
}

func TestScanListBranchFilter(t *testing.T) {
	var gotBranch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBranch = r.URL.Query().Get("branch")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, scansJSON)
	}))
	defer srv.Close()

	resetState(t)
	rootCmd.SetArgs([]string{"scan", "list", "--asset", "ARES-AJ3", "--branch", "feature-xyz", "--org", "acme", "--base-url", srv.URL})
	captureStdout(func() { _ = rootCmd.Execute() })

	if gotBranch != "feature-xyz" {
		t.Errorf("expected --branch to be sent as branch=feature-xyz, got %q", gotBranch)
	}
}

func TestScanVulnsNewFilter(t *testing.T) {
	var gotNew string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNew = r.URL.Query().Get("new")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, scanVulnsNewJSON)
	}))
	defer srv.Close()

	resetState(t)
	rootCmd.SetArgs([]string{"scan", "vulns", "SCAN-9RG", "--new", "--org", "acme", "--base-url", srv.URL})
	captureStdout(func() { _ = rootCmd.Execute() })

	if gotNew != "true" {
		t.Errorf("expected --new to be sent as new=true, got %q", gotNew)
	}
}

func TestScanVulnsNewFalseFilter(t *testing.T) {
	var gotNew string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNew = r.URL.Query().Get("new")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, scanVulnsJSON)
	}))
	defer srv.Close()

	resetState(t)
	rootCmd.SetArgs([]string{"scan", "vulns", "SCAN-9RG", "--new=false", "--org", "acme", "--base-url", srv.URL})
	captureStdout(func() { _ = rootCmd.Execute() })

	if gotNew != "false" {
		t.Errorf("expected --new=false to be sent as new=false, got %q", gotNew)
	}
}

func TestErrors(t *testing.T) {
	t.Run("missing-org", func(t *testing.T) {
		resetState(t)
		rootCmd.SetArgs([]string{"vuln", "list", "--base-url", "http://localhost:9"})
		captureStdout(func() {
			err := rootCmd.Execute()
			if err == nil {
				t.Error("expected error for missing --org, got nil")
			}
		})
	})

	t.Run("scan-list-asset-not-found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"detail":"Not found."}`)
		}))
		defer srv.Close()

		resetState(t)
		rootCmd.SetArgs([]string{"scan", "list", "--asset", "BOGUS-SLUG", "--org", "acme", "--base-url", srv.URL})
		captureStdout(func() {
			err := rootCmd.Execute()
			if err == nil {
				t.Error("expected error for asset not found, got nil")
			}
		})
	})

	t.Run("api-401", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"detail":"Authentication credentials were not provided."}`)
		}))
		defer srv.Close()

		resetState(t)
		rootCmd.SetArgs([]string{"org", "list", "--base-url", srv.URL})
		captureStdout(func() {
			err := rootCmd.Execute()
			if err == nil {
				t.Error("expected error for 401 response, got nil")
			}
		})
	})
}
