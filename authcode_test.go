package oauth2cli_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func TestAuthCodeFlow_GetToken(t *testing.T) {
	// Start an auth server.
	h := authServerHandler{
		t:            t,
		AuthCode:     "AUTH_CODE",
		Scope:        "email",
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
	}
	s := httptest.NewServer(&h)
	defer s.Close()
	endpoint := oauth2.Endpoint{
		AuthURL:  s.URL + "/auth",
		TokenURL: s.URL + "/token",
	}

	// Wait for the local server and open a browser request.
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	openBrowserCh := make(chan string)
	defer close(openBrowserCh)
	go func() {
		select {
		case url := <-openBrowserCh:
			body, err := openBrowserRequest(url)
			if err != nil {
				cancel()
				t.Errorf("Could not open browser request: %+v", err)
			}
			t.Logf("got response body: %s", body)
			if body != oauth2cli.AuthCodeFlowSuccessResponse {
				t.Errorf("response body did not match")
			}
		case <-ctx.Done():
			t.Errorf("Context done while waiting for opening browser: %+v", ctx.Err())
		}
	}()

	// Start a local server and get a token.
	flow := oauth2cli.AuthCodeFlow{
		Config: oauth2.Config{
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			Endpoint:     endpoint,
			Scopes:       []string{"email"},
		},
		SkipOpenBrowser: true,
		ShowLocalServerURL: func(url string) {
			openBrowserCh <- url
		},
		LocalServerMiddleware: loggingMiddleware(t),
	}
	token, err := flow.GetToken(ctx)
	if err != nil {
		t.Errorf("Could not get a token: %+v", err)
		return
	}
	if h.AccessToken != token.AccessToken {
		t.Errorf("AccessToken wants %s but %s", h.AccessToken, token.AccessToken)
	}
	if h.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken wants %s but %s", h.AccessToken, token.AccessToken)
	}
}

func loggingMiddleware(t *testing.T) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("oauth2cli: %s %s", r.Method, r.URL)
			h.ServeHTTP(w, r)
		})
	}
}

func openBrowserRequest(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", errors.Wrapf(err, "could not send a request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.Errorf("status wants 200 but %d", resp.StatusCode)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrapf(err, "could not read response body")
	}
	return string(b), nil
}

type authServerHandler struct {
	t            *testing.T
	Scope        string
	AuthCode     string
	AccessToken  string
	RefreshToken string
}

func (h *authServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serveHTTP(w, r); err != nil {
		h.t.Errorf("authServerHandler error: %s", err)
		http.Error(w, err.Error(), 500)
	}
}

func (h *authServerHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	switch {
	case r.Method == "GET" && r.URL.Path == "/auth":
		q := r.URL.Query()
		scope, state, redirectURI := q.Get("scope"), q.Get("state"), q.Get("redirect_uri")

		if scope == "" {
			return errors.New("scope is missing")
		}
		if state == "" {
			return errors.New("state is missing")
		}
		if redirectURI == "" {
			return errors.New("redirect_uri is missing")
		}
		if h.Scope != scope {
			return errors.Errorf("scope wants %s but %s", h.Scope, scope)
		}
		to := fmt.Sprintf("%s?state=%s&code=%s", redirectURI, state, h.AuthCode)
		http.Redirect(w, r, to, 302)

	case r.Method == "POST" && r.URL.Path == "/token":
		if err := r.ParseForm(); err != nil {
			return errors.Wrapf(err, "error while parsing form")
		}
		code, redirectURI := r.Form.Get("code"), r.Form.Get("redirect_uri")

		if code == "" {
			return errors.New("code is missing")
		}
		if redirectURI == "" {
			return errors.New("redirect_uri is missing")
		}
		if h.AuthCode != code {
			return errors.Errorf("code wants %s but %s", h.AuthCode, code)
		}
		w.Header().Add("Content-Type", "application/json")
		b := fmt.Sprintf(`{
			"access_token": "%s",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token": "%s"
		}`, h.AccessToken, h.RefreshToken)
		if _, err := w.Write([]byte(b)); err != nil {
			return errors.Wrapf(err, "error while writing body")
		}

	default:
		http.NotFound(w, r)
	}
	return nil
}
