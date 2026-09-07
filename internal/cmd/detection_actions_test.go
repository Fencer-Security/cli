package cmd

import (
	"net/http"
	"strings"
	"testing"
)

const detectionJSON = `{"id":55,"slug":"DET-9C4","title":"Suspicious login","severity":1,"status":"under_investigation"}`

func TestDetectionInvestigateSendsCorrectStatus(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, detectionJSON })
	rootCmd.SetArgs([]string{"detection", "investigate", "DET-9C4", "--org", "acme", "--base-url", srv.URL})
	_ = captureStdout(func() { _ = rootCmd.Execute() })

	if (*recs)[0].Path != "/api/v1/org/acme/detections/DET-9C4/transition/" {
		t.Errorf("unexpected path: %s", (*recs)[0].Path)
	}
	if (*recs)[0].Body["status"] != "under_investigation" {
		t.Errorf("unexpected status: %v", (*recs)[0].Body["status"])
	}
}

func TestDetectionResolveRequiresAs(t *testing.T) {
	setupActionTest(t)
	srv, _ := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, detectionJSON })
	rootCmd.SetArgs([]string{"detection", "resolve", "DET-9C4", "--org", "acme", "--base-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "required flag") {
		t.Errorf("expected required flag error, got %v", err)
	}
}

func TestDetectionResolveFalsePositive(t *testing.T) {
	setupActionTest(t)
	srv, recs := newRecordingServer(t, func(r *http.Request) (int, string) { return 200, detectionJSON })
	rootCmd.SetArgs([]string{"detection", "resolve", "DET-9C4", "--as", "false-positive", "--org", "acme", "--base-url", srv.URL})
	_ = captureStdout(func() { _ = rootCmd.Execute() })

	if (*recs)[0].Body["status"] != "resolved_false_positive" {
		t.Errorf("unexpected status: %v", (*recs)[0].Body["status"])
	}
}
