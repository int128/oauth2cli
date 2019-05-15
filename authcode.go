package oauth2cli

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

var defaultMiddleware = func(h http.Handler) http.Handler {
	return h
}

// AuthCodeFlowSuccessResponse is a default response body on authorization success.
const AuthCodeFlowSuccessResponse = `<html><body>OK<script>window.close()</script></body></html>`

// AuthCodeFlow provides the flow with OAuth 2.0 Authorization Code Grant.
// See https://tools.ietf.org/html/rfc6749#section-4.1
type AuthCodeFlow struct {
	Config          oauth2.Config           // OAuth2 config.
	AuthCodeOptions []oauth2.AuthCodeOption // OAuth2 options.
	SkipOpenBrowser bool                    // If set, skip opening browser.

	// Candidates of a port which the local server binds to.
	// If multiple ports are given, it will try the ports in order.
	// If nil or an empty slice is given, it will allocate a free port.
	LocalServerPort []int
	// Response HTML body on authorization success.
	// Default to AuthCodeFlowSuccessResponse.
	LocalServerSuccessResponse string
	// Called when the local server is started. Default to none.
	ShowLocalServerURL func(url string)
	// Middleware for the local server. Default to none.
	LocalServerMiddleware func(h http.Handler) http.Handler
}

// GetToken performs the Authorization Grant Flow and returns a token got from the provider.
//
// This does the following steps:
//
//	1. Start a local server at the port.
//	2. Open a browser and navigate it to the local server.
//	3. Wait for the user authorization.
// 	4. Receive a code via an authorization response (HTTP redirect).
// 	5. Exchange the code and a token.
// 	6. Return the code.
//
func (f *AuthCodeFlow) GetToken(ctx context.Context) (*oauth2.Token, error) {
	listener, err := newLocalhostListener(f.LocalServerPort)
	if err != nil {
		return nil, errors.Wrapf(err, "error while starting a local server")
	}
	defer listener.Close()
	config := f.Config
	if config.RedirectURL == "" {
		config.RedirectURL = listener.URL
	}
	code, err := f.getCode(ctx, listener, config)
	if err != nil {
		return nil, errors.Wrapf(err, "error while receiving an authorization code")
	}
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, errors.Wrapf(err, "error while exchanging authorization code and token")
	}
	return token, nil
}

func (f *AuthCodeFlow) getCode(ctx context.Context, listener *localhostListener, config oauth2.Config) (string, error) {
	state, err := newOAuth2State()
	if err != nil {
		return "", errors.Wrapf(err, "error while state parameter generation")
	}
	middleware := f.LocalServerMiddleware
	if middleware == nil {
		middleware = defaultMiddleware
	}
	successResponse := f.LocalServerSuccessResponse
	if successResponse == "" {
		successResponse = AuthCodeFlowSuccessResponse
	}

	codeCh := make(chan string)
	defer close(codeCh)
	errCh := make(chan error)
	defer close(errCh)
	server := http.Server{
		Handler: middleware(&authCodeFlowHandler{
			config:          config,
			authCodeOptions: f.AuthCodeOptions,
			state:           state,
			successResponse: successResponse,
			gotCode:         codeCh,
			gotError:        errCh,
		}),
	}
	defer server.Shutdown(ctx)

	if f.ShowLocalServerURL != nil {
		f.ShowLocalServerURL(listener.URL)
	}
	if !f.SkipOpenBrowser {
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = browser.OpenURL(listener.URL)
		}()
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return "", err
	case code := <-codeCh:
		return code, nil
	case <-ctx.Done():
		return "", errors.Wrapf(ctx.Err(), "context done while waiting for authorization response")
	}
}

type authCodeFlowHandler struct {
	config          oauth2.Config
	authCodeOptions []oauth2.AuthCodeOption
	state           string
	successResponse string
	gotCode         chan<- string
	gotError        chan<- error
}

func (h *authCodeFlowHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && r.URL.Path == "/" && q.Get("error") != "":
		h.handleErrorResponse(w, r)
	case r.Method == "GET" && r.URL.Path == "/" && q.Get("code") != "":
		h.handleCodeResponse(w, r)
	case r.Method == "GET" && r.URL.Path == "/":
		h.handleIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *authCodeFlowHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	url := h.config.AuthCodeURL(h.state, h.authCodeOptions...)
	http.Redirect(w, r, url, 302)
}

func (h *authCodeFlowHandler) handleCodeResponse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code, state := q.Get("code"), q.Get("state")

	if state != h.state {
		http.Error(w, "authorization error", 500)
		h.gotError <- errors.Errorf("state does not match, wants %s but %s", h.state, state)
		return
	}
	w.Header().Add("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, h.successResponse); err != nil {
		http.Error(w, "server error", 500)
		h.gotError <- errors.Wrapf(err, "error while writing response body")
		return
	}
	h.gotCode <- code
}

func (h *authCodeFlowHandler) handleErrorResponse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	errorCode, errorDescription := q.Get("error"), q.Get("error_description")

	http.Error(w, "authorization error", 500)
	h.gotError <- errors.Errorf("authorization error from server: %s %s", errorCode, errorDescription)
}
