package auth

import (
	"crypto/subtle"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"sync"
)

//go:embed callback.html
var callbackHTML string

var callbackTmpl = template.Must(template.New("callback").Parse(callbackHTML))

type callbackPage struct {
	Title string
	Color string
	RGB   string
	Glow  bool

	Status string
	Info   string
	Hint   string
}

func (p callbackPage) ColorAlpha(a string) template.CSS {
	return template.CSS("rgba(" + p.RGB + "," + a + ")")
}

var (
	callbackSuccess = callbackPage{
		Title:  "authorized",
		Color:  "#3ddc84",
		RGB:    "61,220,132",
		Glow:   true,
		Status: "✓ AUTHORIZED",
		Info:   "token exchange complete · session active",
		Hint:   "you can close this tab and return to the terminal.",
	}
	callbackError = callbackPage{
		Title:  "authorization failed",
		Color:  "#dc4646",
		RGB:    "220,70,70",
		Status: "✗ DENIED",
		Info:   "authorization was denied or an error occurred",
		Hint:   "close this tab and run fencer login to try again.",
	}
)

type callbackHandler struct {
	expectedState string
	mu            sync.Mutex
	used          bool
	codeCh        chan string
	errCh         chan error
}

func (h *callbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")

	h.mu.Lock()
	defer h.mu.Unlock()

	if state == "" {
		serveCallbackPage(w, callbackError)
		return
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(h.expectedState)) != 1 {
		serveCallbackPage(w, callbackError)
		return
	}
	if h.used {
		serveCallbackPage(w, callbackError)
		return
	}

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		h.used = true
		errMsg := r.URL.Query().Get("error_description")
		if errMsg == "" {
			errMsg = errParam
		}
		h.fail(w, fmt.Errorf("authorization denied: %s", errMsg))
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.fail(w, fmt.Errorf("authorization denied: missing code"))
		return
	}

	h.used = true
	select {
	case h.codeCh <- code:
	default:
	}
	serveCallbackPage(w, callbackSuccess)
}

func (h *callbackHandler) fail(w http.ResponseWriter, err error) {
	select {
	case h.errCh <- err:
	default:
	}
	serveCallbackPage(w, callbackError)
}

func serveCallbackPage(w http.ResponseWriter, page callbackPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := callbackTmpl.Execute(w, page); err != nil {
		_, _ = fmt.Fprintln(w, "Authorization complete. You may close this tab.")
	}
}
