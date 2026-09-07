package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var errOAuthRedirect = errors.New("OAuth endpoint returned a redirect")

const (
	cliScopes    = "cli:api:read cli:api:write mcp:vulnerabilities:read"
	callbackPath = "/callback"
)

func oauthHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errOAuthRedirect
		},
	}
}

// Authenticate performs the full OAuth PKCE login flow: starts the callback
// listener, registers a public client with the exact redirect URI, opens the
// browser, and exchanges the code for tokens.
func Authenticate(baseURL string) (clientID string, tokens *TokenData, err error) {
	baseURL, err = NormalizeBaseURL(baseURL)
	if err != nil {
		return "", nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("failed to start callback server: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", port, callbackPath)

	clientID, err = register(baseURL, redirectURI)
	if err != nil {
		_ = listener.Close()
		return "", nil, err
	}

	tokens, err = pkce(baseURL, clientID, redirectURI, listener)
	return clientID, tokens, err
}

// register performs dynamic client registration and returns the client_id.
func register(baseURL, redirectURI string) (string, error) {
	if _, err := NormalizeBaseURL(baseURL); err != nil {
		return "", err
	}
	regURL := strings.TrimRight(baseURL, "/") + "/oauth/register/"

	payload := map[string]interface{}{
		"client_name":                "Fencer CLI",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, regURL, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("registration request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := oauthHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("registration request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse registration response: %w", err)
	}
	return result.ClientID, nil
}

// pkce runs the PKCE authorization code flow using an already-bound listener.
func pkce(baseURL, clientID, redirectURI string, listener net.Listener) (*TokenData, error) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}
	state, err := randomURLToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OAuth state: %w", err)
	}

	handler := &callbackHandler{
		expectedState: state,
		codeCh:        make(chan string, 1),
		errCh:         make(chan error, 1),
	}

	mux := http.NewServeMux()
	mux.Handle(callbackPath, handler)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() { _ = srv.Serve(listener) }()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	authURL := buildAuthURL(baseURL, clientID, redirectURI, challenge, state)
	fmt.Printf("Opening browser for authorization...\nIf it doesn't open, visit:\n%s\n\n", authURL)
	openBrowser(authURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var code string
	select {
	case code = <-handler.codeCh:
	case err = <-handler.errCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("authorization timed out")
	}

	return exchangeCode(baseURL, clientID, code, verifier, redirectURI)
}

// Refresh exchanges a refresh token for new tokens.
func Refresh(baseURL, clientID, refreshToken string) (*TokenData, error) {
	if _, err := NormalizeBaseURL(baseURL); err != nil {
		return nil, err
	}
	tokenURL := strings.TrimRight(baseURL, "/") + "/oauth/token/"

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	tokens, err := postToken(tokenURL, params)
	if err != nil {
		return nil, err
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = refreshToken
	}
	return tokens, nil
}

// Revoke revokes the access token.
func Revoke(baseURL, clientID, token string) error {
	if _, err := NormalizeBaseURL(baseURL); err != nil {
		return err
	}
	revokeURL := strings.TrimRight(baseURL, "/") + "/oauth/revoke_token/"

	params := url.Values{
		"token":     {token},
		"client_id": {clientID},
	}

	resp, err := oauthHTTPClient().PostForm(revokeURL, params)
	if err != nil {
		return fmt.Errorf("revocation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revocation failed with status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func randomURLToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generatePKCE() (verifier, challenge string, err error) {
	verifier, err = randomURLToken()
	if err != nil {
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func buildAuthURL(baseURL, clientID, redirectURI, challenge, state string) string {
	base := strings.TrimRight(baseURL, "/") + "/oauth/authorize/"
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {cliScopes},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return base + "?" + params.Encode()
}

func exchangeCode(baseURL, clientID, code, verifier, redirectURI string) (*TokenData, error) {
	if _, err := NormalizeBaseURL(baseURL); err != nil {
		return nil, err
	}
	tokenURL := strings.TrimRight(baseURL, "/") + "/oauth/token/"

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}

	return postToken(tokenURL, params)
}

func postToken(tokenURL string, params url.Values) (*TokenData, error) {
	resp, err := oauthHTTPClient().PostForm(tokenURL, params)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &apiErr) == nil && (apiErr.ErrorDescription != "" || apiErr.Error != "") {
			msg := apiErr.ErrorDescription
			if msg == "" {
				msg = apiErr.Error
			}
			return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	expiresAt := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return &TokenData{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func openBrowser(rawURL string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{rawURL}
	case "linux":
		cmd = "xdg-open"
		args = []string{rawURL}
	default:
		cmd = "cmd"
		args = []string{"/c", "start", rawURL}
	}

	_ = exec.Command(cmd, args...).Start()
}
