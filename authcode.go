package oauth2cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// AuthCodeFlow provides flow with OAuth 2.0 Authorization Code Grant.
// See https://tools.ietf.org/html/rfc6749#section-4.1
type AuthCodeFlow struct {
	Config          oauth2.Config           // OAuth2 config.
	AuthCodeOptions []oauth2.AuthCodeOption // Options passed to AuthCodeURL().
	LocalServerPort int                     // Local server port. Default to a random port.
	SkipOpenBrowser bool                    // Skip opening browser if it is true.

	ShowLocalServerURL func(url string) // Called when the local server is started. Default to show a message via the logger.
}

// GetToken performs Authorization Grant Flow and returns a token got from the provider.
//
// This does the following steps:
//
// 1. Start a local server at the port.
// 2. Open browser and navigate to the local server.
// 3. Wait for user authorization.
// 4. Receive a code via an authorization response (HTTP redirect).
// 5. Exchange the code and a token.
// 6. Return the code.
//
// Note that this will change Config.RedirectURL to "http://localhost:port" if it is empty.
//
func (f *AuthCodeFlow) GetToken(ctx context.Context) (*oauth2.Token, error) {
	listener, err := newLocalhostListener(f.LocalServerPort)
	if err != nil {
		return nil, errors.Wrapf(err, "error while listening on port %d", f.LocalServerPort)
	}
	defer listener.Close()
	if f.Config.RedirectURL == "" {
		f.Config.RedirectURL = listener.URL
	}
	code, err := f.getCode(ctx, listener)
	if err != nil {
		return nil, errors.Wrapf(err, "error while getting an auth code")
	}
	token, err := f.Config.Exchange(ctx, code)
	if err != nil {
		return nil, errors.Wrapf(err, "error while exchange of code and token")
	}
	return token, nil
}

func (f *AuthCodeFlow) getCode(ctx context.Context, listener *localhostListener) (string, error) {
	state, err := newOAuth2State()
	if err != nil {
		return "", errors.Wrapf(err, "error while state parameter generation")
	}
	codeCh := make(chan string)
	defer close(codeCh)
	errCh := make(chan error)
	defer close(errCh)
	server := http.Server{
		Handler: &authCodeFlowHandler{
			authCodeURL: f.Config.AuthCodeURL(string(state), f.AuthCodeOptions...),
			gotCode: func(code string, gotState string) {
				if gotState == state {
					codeCh <- code
				} else {
					errCh <- errors.Errorf("state does not match, wants %s but %s", state, gotState)
				}
			},
			gotError: func(err error) {
				errCh <- err
			},
		},
	}
	defer server.Shutdown(ctx)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	go func() {
		time.Sleep(500 * time.Millisecond)
		if f.ShowLocalServerURL != nil {
			f.ShowLocalServerURL(listener.URL)
		} else {
			log.Printf("Open %s for authorization", listener.URL)
		}
		if !f.SkipOpenBrowser {
			browser.OpenURL(listener.URL)
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
	authCodeURL string
	gotCode     func(code string, state string)
	gotError    func(err error)
}

func (h *authCodeFlowHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && r.URL.Path == "/" && q.Get("error") != "":
		h.gotError(fmt.Errorf("OAuth Error: %s %s", q.Get("error"), q.Get("error_description")))
		http.Error(w, "OAuth Error", 500)

	case r.Method == "GET" && r.URL.Path == "/" && q.Get("code") != "":
		h.gotCode(q.Get("code"), q.Get("state"))
		w.Header().Add("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>OK<script>window.close()</script></body></html>`)

	case r.Method == "GET" && r.URL.Path == "/":
		http.Redirect(w, r, h.authCodeURL, 302)

	default:
		http.Error(w, "Not Found", 404)
	}
}
