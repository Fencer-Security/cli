package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	contractOrg          = "org/name"
	contractSlug         = "id?x=1"
	contractEncodedOrg   = "org%2Fname"
	contractEncodedSlug  = "id%3Fx=1"
	objectContractJSON   = `{"id":1,"slug":"x","title":"t","severity":1,"status":"open","email":"a@b.c","display_name":"A","role":"admin","is_admin":true,"name":"n","kind_name":"k","provider_name":"p","criticality":50,"message":"ok","kind":"api","description":"d","safe_to_execute":true,"fix_id":1,"attempt_id":1,"details_url":"/","filters":{},"asset_id":42,"asset_type":"repository"}`
	listContractJSON     = `{"count":1,"next":null,"previous":null,"results":[` + objectContractJSON + `]}`
	notFoundContractJSON = `{"detail":"Not found."}`
)

type requestContract struct {
	name        string
	list        bool
	status      int
	wantErr     bool
	method      string
	escapedPath string
	query       url.Values
	bodyHas     []string
	emptyBody   bool
	contentType string
	call        func(*Client) error
}

func TestRequestContracts(t *testing.T) {
	t.Parallel()
	userID := 99
	opts := ListOptions{
		Page:     2,
		PageSize: 25,
		Filters:  url.Values{"order_by": {"severity"}, "q": {"sql injection"}},
	}
	cases := []requestContract{
		{
			name:        "GetCurrentUser",
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/me/",
			call:        func(c *Client) error { _, err := c.GetCurrentUser(contractOrg); return err },
		},
		{
			name:        "ListOrgUsers",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/users/",
			query:       url.Values{"page": {"2"}, "page_size": {"25"}, "search": {"alice"}},
			call: func(c *Client) error {
				_, err := c.ListOrgUsers(contractOrg, "alice", ListOptions{Page: 2, PageSize: 25})
				return err
			},
		},
		{
			name:        "AssignVulnerability",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/assign/",
			bodyHas:     []string{`"user_id":99`},
			contentType: jsonContentType,
			call:        func(c *Client) error { _, err := c.AssignVulnerability(contractOrg, contractSlug, &userID); return err },
		},
		{
			name:        "UnassignVulnerability",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/assign/",
			bodyHas:     []string{`"user_id":null`},
			contentType: jsonContentType,
			call:        func(c *Client) error { _, err := c.AssignVulnerability(contractOrg, contractSlug, nil); return err },
		},
		{
			name:        "IgnoreVulnerability",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/ignore/",
			bodyHas:     []string{`"ignored_reason":"no_fix_available"`, `"ignored_notes":"cannot patch"`},
			contentType: jsonContentType,
			call: func(c *Client) error {
				_, err := c.IgnoreVulnerability(contractOrg, contractSlug, "no_fix_available", "cannot patch")
				return err
			},
		},
		{
			name:        "UnignoreVulnerability",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/unignore/",
			emptyBody:   true,
			call:        func(c *Client) error { _, err := c.UnignoreVulnerability(contractOrg, contractSlug); return err },
		},
		{
			name:        "DeferVulnerability",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/defer/",
			bodyHas:     []string{`"defer_days":30`, `"ignored_reason":"will_not_fix"`},
			contentType: jsonContentType,
			call: func(c *Client) error {
				_, err := c.DeferVulnerability(contractOrg, contractSlug, 30, "will_not_fix", "")
				return err
			},
		},
		{
			name:        "UndeferVulnerability",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/undefer/",
			emptyBody:   true,
			call:        func(c *Client) error { _, err := c.UndeferVulnerability(contractOrg, contractSlug); return err },
		},
		{
			name:        "SetVulnerabilityPriority",
			method:      http.MethodPatch,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/priority/",
			bodyHas:     []string{`"priority_level":"high"`},
			contentType: jsonContentType,
			call: func(c *Client) error {
				_, err := c.SetVulnerabilityPriority(contractOrg, contractSlug, "high")
				return err
			},
		},
		{
			name:        "GetVulnerabilityFixerInstructions",
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/fixer-instructions/",
			call: func(c *Client) error {
				_, err := c.GetVulnerabilityFixerInstructions(contractOrg, contractSlug)
				return err
			},
		},
		{
			name:        "ExecuteVulnerabilityFixer",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/fixer-execute/",
			emptyBody:   true,
			call:        func(c *Client) error { _, err := c.ExecuteVulnerabilityFixer(contractOrg, contractSlug); return err },
		},
		{
			name:        "AssignDetection",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/detections/" + contractEncodedSlug + "/assign/",
			bodyHas:     []string{`"user_id":99`},
			contentType: jsonContentType,
			call:        func(c *Client) error { _, err := c.AssignDetection(contractOrg, contractSlug, &userID); return err },
		},
		{
			name:        "UnassignDetection",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/detections/" + contractEncodedSlug + "/assign/",
			bodyHas:     []string{`"user_id":null`},
			contentType: jsonContentType,
			call:        func(c *Client) error { _, err := c.AssignDetection(contractOrg, contractSlug, nil); return err },
		},
		{
			name:        "TransitionDetection",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/detections/" + contractEncodedSlug + "/transition/",
			bodyHas:     []string{`"status":"under_investigation"`},
			contentType: jsonContentType,
			call: func(c *Client) error {
				_, err := c.TransitionDetection(contractOrg, contractSlug, "under_investigation")
				return err
			},
		},
		{
			name:        "GetOrganizations",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/organizations/api/organizations/",
			query:       url.Values{"page": {"2"}, "page_size": {"25"}},
			call:        func(c *Client) error { _, err := c.GetOrganizations(ListOptions{Page: 2, PageSize: 25}); return err },
		},
		{
			name:        "GetVulnerabilities",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/",
			query:       opts.queryValues(),
			call:        func(c *Client) error { _, err := c.GetVulnerabilities(contractOrg, opts); return err },
		},
		{
			name:        "GetVulnerability",
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/",
			call:        func(c *Client) error { _, err := c.GetVulnerability(contractOrg, contractSlug); return err },
		},
		{
			name:        "GetDetections",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/detections/",
			query:       opts.queryValues(),
			call:        func(c *Client) error { _, err := c.GetDetections(contractOrg, opts); return err },
		},
		{
			name:        "GetDetection",
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/detections/" + contractEncodedSlug + "/",
			call:        func(c *Client) error { _, err := c.GetDetection(contractOrg, contractSlug); return err },
		},
		{
			name:        "GetAssets",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/asset-inventory/",
			query:       opts.queryValues(),
			call:        func(c *Client) error { _, err := c.GetAssets(contractOrg, opts); return err },
		},
		{
			name:        "GetAssetInventoryConfig",
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/asset-inventory/config/",
			call:        func(c *Client) error { _, err := c.GetAssetInventoryConfig(contractOrg); return err },
		},
		{
			name:        "GetAssetResource",
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/asset-inventory/" + contractEncodedSlug + "/",
			call:        func(c *Client) error { _, err := c.GetAssetResource(contractOrg, contractSlug); return err },
		},
		{
			name:        "SetAssetCriticality",
			method:      http.MethodPatch,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/asset-inventory/" + contractEncodedSlug + "/",
			bodyHas:     []string{`"criticality":80`},
			contentType: jsonContentType,
			call:        func(c *Client) error { _, err := c.SetAssetCriticality(contractOrg, contractSlug, 80); return err },
		},
		{
			name:        "GetAssetScans",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/asset-inventory/" + contractEncodedSlug + "/scans/",
			query:       opts.queryValues(),
			call:        func(c *Client) error { _, err := c.GetAssetScans(contractOrg, contractSlug, opts); return err },
		},
		{
			name:        "ScheduleScan",
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/asset-inventory/" + contractEncodedSlug + "/trigger-scan/",
			bodyHas:     []string{`"branch":"main"`},
			contentType: jsonContentType,
			call:        func(c *Client) error { _, err := c.ScheduleScan(contractOrg, contractSlug, "main"); return err },
		},
		{
			name:        "GetScan",
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/scans/" + contractEncodedSlug + "/",
			call:        func(c *Client) error { _, err := c.GetScan(contractOrg, contractSlug); return err },
		},
		{
			name:        "GetScanVulnerabilities",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/scans/" + contractEncodedSlug + "/vulnerability-snapshots/",
			query:       opts.queryValues(),
			call:        func(c *Client) error { _, err := c.GetScanVulnerabilities(contractOrg, contractSlug, opts); return err },
		},
		{
			name:        "GetIdentities",
			list:        true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/identities/",
			query:       opts.queryValues(),
			call:        func(c *Client) error { _, err := c.GetIdentities(contractOrg, opts); return err },
		},
		{
			name:        "GetVulnerabilityNotFound",
			status:      http.StatusNotFound,
			wantErr:     true,
			method:      http.MethodGet,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/",
			call:        func(c *Client) error { _, err := c.GetVulnerability(contractOrg, contractSlug); return err },
		},
		{
			name:        "UnignoreVulnerabilityNotFound",
			status:      http.StatusNotFound,
			wantErr:     true,
			method:      http.MethodPost,
			escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/unignore/",
			emptyBody:   true,
			call:        func(c *Client) error { _, err := c.UnignoreVulnerability(contractOrg, contractSlug); return err },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertRequestContract(t, tc)
		})
	}
}

func assertRequestContract(t *testing.T, tc requestContract) {
	t.Helper()
	status := tc.status
	if status == 0 {
		status = http.StatusOK
	}
	body := objectContractJSON
	if tc.list {
		body = listContractJSON
	}
	if status >= 400 {
		body = notFoundContractJSON
	}

	var got *http.Request
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		cloned := r.Clone(r.Context())
		got = cloned
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	err := tc.call(New(srv.URL, srv.Client()))
	if tc.wantErr {
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Fatalf("expected 404 in error, got %v", err)
		}
	} else if err != nil {
		t.Fatalf("call: %v", err)
	}
	if got == nil {
		t.Fatal("no request captured")
	}
	if got.Method != tc.method {
		t.Fatalf("method = %s, want %s", got.Method, tc.method)
	}
	if got.URL.EscapedPath() != tc.escapedPath {
		t.Fatalf("escaped path = %q, want %q (decoded %q query %q)", got.URL.EscapedPath(), tc.escapedPath, got.URL.Path, got.URL.RawQuery)
	}
	if _, leaked := got.URL.Query()["x"]; leaked {
		t.Fatalf("slug reserved characters leaked into query: %q", got.URL.RawQuery)
	}
	if got.Header.Get("Accept") != acceptHeaderValue {
		t.Fatalf("Accept = %q, want %q", got.Header.Get("Accept"), acceptHeaderValue)
	}
	if got.Header.Get("Content-Type") != tc.contentType {
		t.Fatalf("Content-Type = %q, want %q", got.Header.Get("Content-Type"), tc.contentType)
	}
	if tc.emptyBody && len(gotBody) != 0 {
		t.Fatalf("expected empty body, got %q", gotBody)
	}
	for _, fragment := range tc.bodyHas {
		if !strings.Contains(string(gotBody), fragment) {
			t.Fatalf("body %q missing %q", gotBody, fragment)
		}
	}
	gotQuery := got.URL.Query()
	for key, values := range tc.query {
		if gotQuery.Get(key) != values[0] {
			t.Fatalf("query[%s] = %q, want %q (raw %q)", key, gotQuery.Get(key), values[0], got.URL.RawQuery)
		}
	}
}

func TestIgnoreEmptyBodyStillSendsVendorContentType(t *testing.T) {
	t.Parallel()
	assertRequestContract(t, requestContract{
		name:        "IgnoreVulnerabilityEmpty",
		method:      http.MethodPost,
		escapedPath: "/api/v1/org/" + contractEncodedOrg + "/vulnerabilities/" + contractEncodedSlug + "/ignore/",
		bodyHas:     []string{`{}`},
		contentType: jsonContentType,
		call:        func(c *Client) error { _, err := c.IgnoreVulnerability(contractOrg, contractSlug, "", ""); return err },
	})
}

func TestScheduleScanEmptyBranchSendsObjectWithoutBranch(t *testing.T) {
	t.Parallel()
	assertRequestContract(t, requestContract{
		method:      http.MethodPost,
		escapedPath: "/api/v1/org/" + contractEncodedOrg + "/asset-inventory/" + contractEncodedSlug + "/trigger-scan/",
		bodyHas:     []string{`{}`},
		contentType: jsonContentType,
		call:        func(c *Client) error { _, err := c.ScheduleScan(contractOrg, contractSlug, ""); return err },
	})
}
