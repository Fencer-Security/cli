package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestGetSetsVersionedAcceptHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL, srv.Client())
	var dest map[string]any
	if err := client.Get("/test", url.Values{"page": {"1"}}, &dest); err != nil {
		t.Fatalf("Get returned error: %v", err)
	}

	if gotAccept != acceptHeaderValue {
		t.Fatalf("expected Accept %q, got %q", acceptHeaderValue, gotAccept)
	}
}

func TestPostNilOmitsBodyAndContentType(t *testing.T) {
	var gotContentType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL, srv.Client())
	var dest map[string]any
	if err := client.Post("/test", nil, &dest); err != nil {
		t.Fatalf("Post returned error: %v", err)
	}
	if gotContentType != "" {
		t.Fatalf("expected no Content-Type, got %q", gotContentType)
	}
	if len(gotBody) != 0 {
		t.Fatalf("expected empty body, got %q", gotBody)
	}
}

func TestPostSetsVersionedAcceptHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL, srv.Client())
	var dest map[string]any
	if err := client.Post("/test", map[string]string{"k": "v"}, &dest); err != nil {
		t.Fatalf("Post returned error: %v", err)
	}

	if gotAccept != acceptHeaderValue {
		t.Fatalf("expected Accept %q, got %q", acceptHeaderValue, gotAccept)
	}
}

func TestDecodeResponse426ReturnsUpgradeRequiredError(t *testing.T) {
	body := `{"detail":"Your client version (0.9.0) is below the minimum required version (1.0.0). Please upgrade.","min_client_version":"1.0.0","docs_url":"https://docs.fencer.dev/cli/upgrading/"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUpgradeRequired)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := New(srv.URL, srv.Client())
	err := client.Get("/test", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var upgradeErr *UpgradeRequiredError
	if !errors.As(err, &upgradeErr) {
		t.Fatalf("expected UpgradeRequiredError, got %T: %v", err, err)
	}
	if upgradeErr.MinClientVersion != "1.0.0" {
		t.Errorf("expected min_client_version=1.0.0, got %s", upgradeErr.MinClientVersion)
	}
	if upgradeErr.DocsURL != "https://docs.fencer.dev/cli/upgrading/" {
		t.Errorf("expected docs_url, got %s", upgradeErr.DocsURL)
	}
}

func TestDecodeResponse426FallbackOnMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUpgradeRequired)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	client := New(srv.URL, srv.Client())
	err := client.Get("/test", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var upgradeErr *UpgradeRequiredError
	if errors.As(err, &upgradeErr) {
		t.Fatal("expected generic error for malformed body, got UpgradeRequiredError")
	}
}

func TestUpgradeRequiredErrorMessage(t *testing.T) {
	err := &UpgradeRequiredError{
		Detail:           "Please upgrade.",
		MinClientVersion: "1.0.0",
		DocsURL:          "https://docs.fencer.dev/cli/upgrading/",
	}
	msg := err.Error()
	if msg != "Please upgrade.\nUpgrade instructions: https://docs.fencer.dev/cli/upgrading/" {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestUpgradeRequiredErrorMessageWithoutDocsURL(t *testing.T) {
	err := &UpgradeRequiredError{
		Detail:           "Please upgrade.",
		MinClientVersion: "1.0.0",
	}
	if err.Error() != "Please upgrade." {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

func TestGetAssetResourcePopulatesAssetIDAndType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/org/acme/asset-inventory/repo-abc123/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":7,"slug":"repo-abc123","asset_id":42,"asset_type":"repository","kind_name":"Repository","provider_name":"GitHub","criticality":80}`))
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL, srv.Client())
	asset, err := client.GetAssetResource("acme", "repo-abc123")
	if err != nil {
		t.Fatalf("GetAssetResource returned error: %v", err)
	}
	if asset.AssetID != 42 {
		t.Errorf("expected AssetID=42, got %d", asset.AssetID)
	}
	if asset.AssetType != "repository" {
		t.Errorf("expected AssetType=repository, got %q", asset.AssetType)
	}
	if asset.Asset != "repository:42" {
		t.Errorf("expected Asset=repository:42, got %q", asset.Asset)
	}
}

func TestScheduleScanPostsBranchAndDecodesScanID(t *testing.T) {
	var gotPath string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"Scan scheduled","scan_id":123,"slug":"SCAN-123"}`))
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL, srv.Client())
	resp, err := client.ScheduleScan("acme", "ARES-AJ3", "main")
	if err != nil {
		t.Fatalf("ScheduleScan returned error: %v", err)
	}

	if gotPath != "/api/v1/org/acme/asset-inventory/ARES-AJ3/trigger-scan/" {
		t.Errorf("unexpected path: %s", gotPath)
	}
	if gotBody["branch"] != "main" {
		t.Errorf("expected branch=main in body, got %v", gotBody)
	}
	if resp.Message != "Scan scheduled" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.ScanID == nil || *resp.ScanID != 123 {
		t.Errorf("expected scan_id=123, got %v", resp.ScanID)
	}
	if resp.Slug == nil || *resp.Slug != "SCAN-123" {
		t.Errorf("expected slug=SCAN-123, got %v", resp.Slug)
	}
}

func TestScheduleScanOmitsBranchWhenEmpty(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"Scan scheduled","scan_id":1}`))
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL, srv.Client())
	if _, err := client.ScheduleScan("acme", "ARES-CLD1", ""); err != nil {
		t.Fatalf("ScheduleScan returned error: %v", err)
	}
	if _, ok := gotBody["branch"]; ok {
		t.Errorf("expected branch to be omitted, got %v", gotBody)
	}
}
