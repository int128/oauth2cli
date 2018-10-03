package oauth2cli

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// AuthCodeFlow provides flow with OAuth 2.0 Authorization Code Grant.
// See https://tools.ietf.org/html/rfc6749#section-4.1
type AuthCodeFlow struct {
	// OAuth2 configuration.
	// RedirectURL will be set to "http://localhost:port" if it is empty.
	Config oauth2.Config

	AuthCodeOptions []oauth2.AuthCodeOption // Options passed to AuthCodeURL().
	ServerPort      int                     // HTTP server port. Default to a random port.
	SkipOpenBrowser bool                    // Skip opening browser if it is true.
}

// GetToken retrieves a token from the provider.
func (f *AuthCodeFlow) GetToken(ctx context.Context) (*oauth2.Token, error) {
	code, err := f.getAuthCode(ctx)
	if err != nil {
		return nil, fmt.Errorf("Could not get an auth code: %s", err)
	}
	token, err := f.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("Could not exchange token: %s", err)
	}
	return token, nil
}

func (f *AuthCodeFlow) getAuthCode(ctx context.Context) (string, error) {
	state, err := newOAuth2State()
	if err != nil {
		return "", fmt.Errorf("Could not generate state parameter: %s", err)
	}
	codeCh := make(chan string)
	defer close(codeCh)
	errCh := make(chan error)
	defer close(errCh)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", f.ServerPort))
	if err != nil {
		return "", fmt.Errorf("Could not listen to port %d", f.ServerPort)
	}
	defer listener.Close()
	port, err := extractPort(listener.Addr())
	if err != nil {
		return "", fmt.Errorf("Could not determine listening port: %s", err)
	}
	log.Printf("Listening to port %d", port)
	if f.Config.RedirectURL == "" {
		f.Config.RedirectURL = fmt.Sprintf("http://localhost:%d/", port)
	}

	server := &http.Server{
		Handler: &authCodeHandler{
			authCodeURL: f.Config.AuthCodeURL(string(state), f.AuthCodeOptions...),
			gotCode: func(code string, gotState oauth2State) {
				if gotState == state {
					codeCh <- code
				} else {
					errCh <- fmt.Errorf("State does not match, wants %s but %s", state, gotState)
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
		log.Printf("Open http://localhost:%d for authorization", port)
		if !f.SkipOpenBrowser {
			time.Sleep(500 * time.Millisecond)
			browser.OpenURL(fmt.Sprintf("http://localhost:%d/", port))
		}
	}()
	select {
	case err := <-errCh:
		return "", err
	case code := <-codeCh:
		return code, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func extractPort(addr net.Addr) (int, error) {
	s := strings.SplitN(addr.String(), ":", 2)
	if len(s) != 2 {
		return 0, fmt.Errorf("Invalid address: %s", addr)
	}
	p, err := strconv.Atoi(s[1])
	if err != nil {
		return 0, fmt.Errorf("Not number %s: %s", addr, err)
	}
	return p, nil
}

type authCodeHandler struct {
	authCodeURL string
	gotCode     func(code string, state oauth2State)
	gotError    func(err error)
}

func (h *authCodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.RequestURI)
	m := r.Method
	p := r.URL.Path
	q := r.URL.Query()
	switch {
	case m == "GET" && p == "/" && q.Get("error") != "":
		h.gotError(fmt.Errorf("OAuth Error: %s %s", q.Get("error"), q.Get("error_description")))
		http.Error(w, "OAuth Error", 500)

	case m == "GET" && p == "/" && q.Get("code") != "":
		h.gotCode(q.Get("code"), oauth2State(q.Get("state")))
		w.Header().Add("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>OK<script>window.close()</script></body></html>`)

	case m == "GET" && p == "/":
		http.Redirect(w, r, h.authCodeURL, 302)

	default:
		http.Error(w, "Not Found", 404)
	}
}
