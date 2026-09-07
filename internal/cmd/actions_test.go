package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fencer/cli/internal/config"
)

// recordedRequest captures one HTTP call made by the CLI during a test.
type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Body   map[string]any
}

// newRecordingServer returns an httptest server that records every request and
// lets the caller provide a route-aware handler for responses.
func newRecordingServer(t *testing.T, respond func(r *http.Request) (int, string)) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var recorded []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recordedRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery}
		if len(body) > 0 {
			_ = json.Unmarshal(body, &rec.Body)
		}
		recorded = append(recorded, rec)

		status, payload := respond(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, payload)
	}))
	t.Cleanup(srv.Close)
	return srv, &recorded
}

// setupActionTest isolates the user cache to a per-test temp dir and auto-confirms.
func setupActionTest(t *testing.T) {
	t.Helper()
	resetState(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	origTTY := isStdinTTY
	isStdinTTY = func() bool { return false }
	t.Cleanup(func() { isStdinTTY = origTTY })
	yesFlag = true
}

const (
	assignedVulnJSON  = `{"id":42,"slug":"vuln-abc","title":"X","severity":1,"status":"open","asset_id":7,"asset_type":"repository","asset_name":"web-app","web_url":"u"}`
	orgUsersAliceJSON = `{"count":1,"next":null,"previous":null,"results":[{"id":99,"name":"Alice","email":"alice@acme.dev","avatar_url":null}]}`
	currentUserJSON   = `{"id":77,"email":"me@acme.dev","display_name":"Me","role":"admin","is_admin":true}`
)

func TestVulnAssignByEmail(t *testing.T) {
	setupActionTest(t)

	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/users/":
			return 200, orgUsersAliceJSON
		case "/api/v1/org/acme/vulnerabilities/vuln-abc/assign/":
			return 200, assignedVulnJSON
		}
		return 404, `{"detail":"not found"}`
	})

	rootCmd.SetArgs([]string{"vuln", "assign", "vuln-abc", "--email", "alice@acme.dev", "--org", "acme", "--base-url", srv.URL})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	if !strings.Contains(out, "Assigned vuln-abc to alice@acme.dev") {
		t.Errorf("unexpected output: %q", out)
	}
	if len(*recs) != 2 {
		t.Fatalf("expected 2 requests (lookup + assign), got %d: %+v", len(*recs), *recs)
	}
	assign := (*recs)[1]
	if assign.Method != "POST" || assign.Path != "/api/v1/org/acme/vulnerabilities/vuln-abc/assign/" {
		t.Errorf("unexpected assign request: %+v", assign)
	}
	if got := assign.Body["user_id"]; got != float64(99) {
		t.Errorf("expected user_id=99, got %v", got)
	}
}

func TestVulnAssignCacheHit(t *testing.T) {
	setupActionTest(t)

	// Pre-populate cache.
	path, err := config.UserCacheFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path,
		[]byte(`{"orgs":{"acme":{"emails":{"alice@acme.dev":99}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, assignedVulnJSON
	})

	rootCmd.SetArgs([]string{"vuln", "assign", "vuln-abc", "--email", "alice@acme.dev", "--org", "acme", "--base-url", srv.URL})
	_ = captureStdout(func() { _ = rootCmd.Execute() })

	if len(*recs) != 1 {
		t.Fatalf("expected cache hit (1 request), got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Path != "/api/v1/org/acme/vulnerabilities/vuln-abc/assign/" {
		t.Errorf("unexpected path: %s", (*recs)[0].Path)
	}
}

func TestVulnAssignMe(t *testing.T) {
	setupActionTest(t)

	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/me/":
			return 200, currentUserJSON
		case "/api/v1/org/acme/vulnerabilities/vuln-abc/assign/":
			return 200, assignedVulnJSON
		}
		return 404, `{}`
	})

	rootCmd.SetArgs([]string{"vuln", "assign", "vuln-abc", "--me", "--org", "acme", "--base-url", srv.URL})
	_ = captureStdout(func() { _ = rootCmd.Execute() })

	if len(*recs) != 2 {
		t.Fatalf("expected 2 requests, got %d: %+v", len(*recs), *recs)
	}
	if got := (*recs)[1].Body["user_id"]; got != float64(77) {
		t.Errorf("expected user_id=77, got %v", got)
	}
}

func TestVulnUnassignPostsNullUserID(t *testing.T) {
	setupActionTest(t)
	currentVulnJSON := `{"id":42,"slug":"vuln-abc","title":"X","severity":1,"status":"open","asset_id":7,"asset_type":"repository","asset_name":"web-app","assignee_email":"alice@acme.dev","assignee_name":"Alice","web_url":"u"}`
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.Method {
		case http.MethodGet:
			return 200, currentVulnJSON
		case http.MethodPost:
			return 200, assignedVulnJSON
		}
		return 404, `{}`
	})
	rootCmd.SetArgs([]string{"vuln", "unassign", "vuln-abc", "--org", "acme", "--base-url", srv.URL})
	_ = captureStdout(func() { _ = rootCmd.Execute() })

	if len(*recs) != 3 {
		t.Fatalf("expected 3 requests (GET current, GET confirm, POST assign), got %d: %+v", len(*recs), *recs)
	}
	post := (*recs)[2]
	if post.Method != "POST" || post.Path != "/api/v1/org/acme/vulnerabilities/vuln-abc/assign/" {
		t.Errorf("unexpected POST: %+v", post)
	}
	if post.Body["user_id"] != nil {
		t.Errorf("expected user_id=null, got %v", post.Body["user_id"])
	}
}

func TestVulnUnassignSkipsWhenAlreadyUnassigned(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, assignedVulnJSON
	})
	rootCmd.SetArgs([]string{"vuln", "unassign", "vuln-abc", "--org", "acme", "--base-url", srv.URL})
	out := captureStdout(func() { _ = rootCmd.Execute() })

	if len(*recs) != 1 || (*recs)[0].Method != "GET" {
		t.Fatalf("expected single GET request, got %+v", *recs)
	}
	if !strings.Contains(out, "already unassigned") {
		t.Errorf("expected 'already unassigned' message, got %q", out)
	}
}

func TestVulnUnassignAlreadyUnassignedJSON(t *testing.T) {
	setupActionTest(t)
	srv, _ := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, assignedVulnJSON
	})
	rootCmd.SetArgs([]string{"vuln", "unassign", "vuln-abc", "--org", "acme", "--base-url", srv.URL, "--output", "json"})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected valid JSON, got %q", out)
	}
	if !strings.Contains(out, `"already_unassigned": true`) {
		t.Errorf("expected already_unassigned in JSON, got %q", out)
	}
}

func TestDetectionUnassignAlreadyUnassignedJSON(t *testing.T) {
	setupActionTest(t)
	srv, _ := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, detectionJSON
	})
	rootCmd.SetArgs([]string{"detection", "unassign", "DET-9C4", "--org", "acme", "--base-url", srv.URL, "--output", "json"})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected valid JSON, got %q", out)
	}
	if !strings.Contains(out, `"already_unassigned": true`) {
		t.Errorf("expected already_unassigned in JSON, got %q", out)
	}
}

func TestVulnIgnoreSendsReasonAndNotes(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, assignedVulnJSON
	})
	rootCmd.SetArgs([]string{"vuln", "ignore", "vuln-abc",
		"--reason", "false_positive", "--notes", "checked",
		"--org", "acme", "--base-url", srv.URL})
	_ = captureStdout(func() { _ = rootCmd.Execute() })

	body := (*recs)[0].Body
	if body["ignored_reason"] != "false_positive" || body["ignored_notes"] != "checked" {
		t.Errorf("unexpected body: %+v", body)
	}
}

func TestVulnIgnoreRejectsInvalidReason(t *testing.T) {
	setupActionTest(t)
	srv, _ := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, assignedVulnJSON })
	rootCmd.SetArgs([]string{"vuln", "ignore", "vuln-abc", "--reason", "bogus", "--org", "acme", "--base-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid --reason") {
		t.Errorf("expected invalid reason error, got %v", err)
	}
}

func TestVulnDeferRejectsInvalidDays(t *testing.T) {
	setupActionTest(t)
	srv, _ := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, assignedVulnJSON })
	rootCmd.SetArgs([]string{"vuln", "defer", "vuln-abc", "--days", "5", "--org", "acme", "--base-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--days must be") {
		t.Errorf("expected invalid days error, got %v", err)
	}
}

func TestVulnUnignoreNoBody(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, assignedVulnJSON })
	rootCmd.SetArgs([]string{"vuln", "unignore", "vuln-abc", "--org", "acme", "--base-url", srv.URL})
	_ = captureStdout(func() { _ = rootCmd.Execute() })

	if (*recs)[0].Path != "/api/v1/org/acme/vulnerabilities/vuln-abc/unignore/" {
		t.Errorf("unexpected path: %s", (*recs)[0].Path)
	}
}

func TestVulnPrioritySendsLevel(t *testing.T) {
	setupActionTest(t)
	priorityVulnJSON := `{"id":42,"slug":"vuln-abc","title":"X","severity":1,"status":"open","priority_level":"high","asset_id":7,"asset_type":"repository","asset_name":"web-app","web_url":"u"}`
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, priorityVulnJSON
	})

	rootCmd.SetArgs([]string{"vuln", "priority", "vuln-abc",
		"--level", "high",
		"--org", "acme", "--base-url", srv.URL})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	rec := (*recs)[0]
	if rec.Method != "PATCH" || rec.Path != "/api/v1/org/acme/vulnerabilities/vuln-abc/priority/" {
		t.Errorf("unexpected request: %+v", rec)
	}
	if rec.Body["priority_level"] != "high" {
		t.Errorf("expected priority_level=high, got %v", rec.Body["priority_level"])
	}
	if !strings.Contains(out, "Set priority on vuln-abc to high") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestVulnPriorityRejectsInvalidLevel(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, assignedVulnJSON })
	rootCmd.SetArgs([]string{"vuln", "priority", "vuln-abc",
		"--level", "bogus",
		"--org", "acme", "--base-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--level must be one of") {
		t.Errorf("expected invalid level error, got %v", err)
	}
	if len(*recs) != 0 {
		t.Errorf("expected no requests on validation failure, got %d", len(*recs))
	}
}

func TestAssetCriticalitySendsScore(t *testing.T) {
	setupActionTest(t)
	assetJSON := `{"id":1,"slug":"AR-9R4","kind_name":"Repo","category":"code","description":"d","belongs_to":"team","asset_id":7,"asset_type":"repository","criticality":42}`
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, assetJSON
	})

	rootCmd.SetArgs([]string{"asset", "criticality", "AR-9R4",
		"--score", "42",
		"--org", "acme", "--base-url", srv.URL})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d: %+v", len(*recs), *recs)
	}
	rec := (*recs)[0]
	if rec.Method != "PATCH" || rec.Path != "/api/v1/org/acme/asset-inventory/AR-9R4/" {
		t.Errorf("unexpected request: %+v", rec)
	}
	if got := rec.Body["criticality"]; got != float64(42) {
		t.Errorf("expected criticality=42, got %v", got)
	}
	if !strings.Contains(out, "Set criticality on asset AR-9R4 to 42") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestAssetCriticalityRejectsOutOfRange(t *testing.T) {
	cases := []string{"101", "-1"}
	for _, score := range cases {
		t.Run("score="+score, func(t *testing.T) {
			setupActionTest(t)
			srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, `{}` })
			rootCmd.SetArgs([]string{"asset", "criticality", "AR-9R4",
				"--score", score,
				"--org", "acme", "--base-url", srv.URL})
			err := rootCmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "--score must be between 0 and 100") {
				t.Errorf("expected out-of-range error, got %v", err)
			}
			if len(*recs) != 0 {
				t.Errorf("expected no requests on validation failure, got %d", len(*recs))
			}
		})
	}
}

func TestAssetListTopLevelFlag(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, `{"count":0,"next":null,"previous":null,"results":[]}`
	})
	rootCmd.SetArgs([]string{"asset", "list", "--top-level",
		"--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*recs))
	}
	if (*recs)[0].Query == "" || !strings.Contains((*recs)[0].Query, "top_level=true") {
		t.Errorf("expected top_level=true in query, got %q", (*recs)[0].Query)
	}
}

func TestAssetListOptsOutOfVulnerabilityCount(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		return 200, `{"count":0,"next":null,"previous":null,"results":[]}`
	})
	rootCmd.SetArgs([]string{"asset", "list", "--org", "acme", "--base-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(*recs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*recs))
	}
	if !strings.Contains((*recs)[0].Query, "include_vulnerability_count=false") {
		t.Errorf("expected include_vulnerability_count=false in query, got %q", (*recs)[0].Query)
	}
}

func TestVulnFixSchedulesAttempt(t *testing.T) {
	setupActionTest(t)
	instructionsJSON := `{"kind":"api","description":"Please fix the following resource: path/to/file.","cli_command":null,"safe_to_execute":true}`
	executeJSON := `{"fix_id":5,"attempt_id":9,"status":"pending","details_url":"/a/acme/vulnerabilities/vuln-abc/fix/attempts/9/"}`
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/org/acme/vulnerabilities/vuln-abc/fixer-instructions/":
			return 200, instructionsJSON
		case "/api/v1/org/acme/vulnerabilities/vuln-abc/fixer-execute/":
			return 200, executeJSON
		}
		return 404, `{"detail":"not found"}`
	})

	rootCmd.SetArgs([]string{"vuln", "fix", "vuln-abc", "--org", "acme", "--base-url", srv.URL})
	out := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	if len(*recs) != 3 {
		t.Fatalf("expected 3 requests (confirm instructions + execute safety check + execute), got %d: %+v", len(*recs), *recs)
	}
	if (*recs)[0].Method != "GET" || (*recs)[1].Method != "GET" || (*recs)[2].Method != "POST" {
		t.Errorf("unexpected request methods: %+v", *recs)
	}
	if !strings.Contains(out, "Scheduled fix for vuln-abc (status: pending)") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestVulnFixRejectsUnsafeFixer(t *testing.T) {
	setupActionTest(t)
	instructionsJSON := `{"kind":"ai","description":"Fencer will launch an AI agent to propose changes to resolve this vulnerability.","cli_command":null,"safe_to_execute":false}`
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, instructionsJSON })

	rootCmd.SetArgs([]string{"vuln", "fix", "vuln-abc", "--org", "acme", "--base-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "not safe to execute automatically") {
		t.Errorf("expected unsafe fixer error, got %v", err)
	}
	if len(*recs) != 1 {
		t.Errorf("expected only the instructions request, got %d: %+v", len(*recs), *recs)
	}
}

func TestConfirmRequiresYesWhenNonTTY(t *testing.T) {
	setupActionTest(t)
	yesFlag = false // force the prompt
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, assignedVulnJSON })
	rootCmd.SetArgs([]string{"vuln", "unignore", "vuln-abc", "--org", "acme", "--base-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("expected --yes required error, got %v", err)
	}
	if len(*recs) != 0 {
		t.Errorf("expected no requests when confirmation fails, got %d", len(*recs))
	}
}
