package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newCallbackHandler(state string) *callbackHandler {
	return &callbackHandler{
		expectedState: state,
		codeCh:        make(chan string, 1),
		errCh:         make(chan error, 1),
	}
}

func TestCallbackRejectsMissingState(t *testing.T) {
	h := newCallbackHandler("expected-state")
	req := httptest.NewRequest(http.MethodGet, "/callback?code=abc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "DENIED") {
		t.Fatalf("expected error page, got %s", rec.Body.String())
	}
	select {
	case code := <-h.codeCh:
		t.Fatalf("missing state must not yield code %q", code)
	default:
	}
}

func TestCallbackRejectsMismatchedState(t *testing.T) {
	h := newCallbackHandler("expected-state")
	req := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=wrong", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "DENIED") {
		t.Fatalf("expected error page, got %s", rec.Body.String())
	}
	select {
	case code := <-h.codeCh:
		t.Fatalf("mismatched state must not yield code %q", code)
	default:
	}

	req = httptest.NewRequest(http.MethodGet, "/callback?code=real-code&state=expected-state", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	select {
	case code := <-h.codeCh:
		if code != "real-code" {
			t.Fatalf("got code %q, want real-code", code)
		}
	default:
		t.Fatal("valid state after mismatch should still succeed")
	}
}

func TestCallbackRejectsReusedState(t *testing.T) {
	h := newCallbackHandler("expected-state")
	req := httptest.NewRequest(http.MethodGet, "/callback?code=first&state=expected-state", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got := <-h.codeCh; got != "first" {
		t.Fatalf("first callback code = %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/callback?code=second&state=expected-state", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "DENIED") {
		t.Fatalf("expected reused state to be rejected, got %s", rec.Body.String())
	}
	select {
	case code := <-h.codeCh:
		t.Fatalf("reused state must not yield code %q", code)
	default:
	}
}

func TestBuildAuthURLIncludesState(t *testing.T) {
	raw := buildAuthURL("https://app.fencer.dev", "client", "http://127.0.0.1:9/callback", "challenge", "csrf-state")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("state") != "csrf-state" {
		t.Fatalf("state = %q", q.Get("state"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
}

func TestRefreshPreservesRefreshTokenWhenOmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token/" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("refresh_token") != "original-refresh" {
			t.Errorf("refresh_token = %q", r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)

	tokens, err := Refresh(srv.URL, "client", "original-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "new-access" {
		t.Fatalf("access = %q", tokens.AccessToken)
	}
	if tokens.RefreshToken != "original-refresh" {
		t.Fatalf("refresh = %q, want original-refresh", tokens.RefreshToken)
	}
}

func TestRefreshReplacesRefreshTokenWhenRotated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"rotated","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)

	tokens, err := Refresh(srv.URL, "client", "original-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.RefreshToken != "rotated" {
		t.Fatalf("refresh = %q, want rotated", tokens.RefreshToken)
	}
}

func TestOAuthNetworkOperationsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("FENCER_HTTP_TIMEOUT", "30ms")

	if _, err := register(srv.URL, "http://127.0.0.1:1/callback"); err == nil {
		t.Fatal("expected registration timeout")
	}
	if _, err := Refresh(srv.URL, "client", "refresh"); err == nil {
		t.Fatal("expected refresh timeout")
	}
	if err := Revoke(srv.URL, "client", "token"); err == nil {
		t.Fatal("expected revoke timeout")
	}
}

func TestRefreshRejectsInsecureProductionURL(t *testing.T) {
	_, err := Refresh("http://app.fencer.dev", "client", "refresh")
	if err == nil {
		t.Fatal("expected insecure production URL to be rejected")
	}
}

func TestOAuthClientDoesNotFollowRedirects(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token request followed a redirect")
		_, _ = io.WriteString(w, `{"access_token":"leaked","expires_in":3600}`)
	}))
	t.Cleanup(dest.Close)

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/oauth/token/", http.StatusFound)
	}))
	t.Cleanup(src.Close)

	_, err := Refresh(src.URL, "client", "refresh")
	if err == nil {
		t.Fatal("expected redirect to fail token exchange")
	}
}

func TestRandomURLTokenIsUnique(t *testing.T) {
	a, err := randomURLToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomURLToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected distinct tokens")
	}
	if len(a) < 32 {
		t.Fatalf("token too short: %q", a)
	}
}
