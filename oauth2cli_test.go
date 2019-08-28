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
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

func TestAuthCodeFlow_GetToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Start an auth server.
		h := authServerHandler{
			t: t,
			NewAuthResponse: func(scope, state, redirectURI string) string {
				if w := "email profile"; scope != w {
					t.Errorf("scope wants %s but %s", w, scope)
					return fmt.Sprintf("%s?error=invalid_scope", redirectURI)
				}
				return fmt.Sprintf("%s?state=%s&code=%s", redirectURI, state, "AUTH_CODE")
			},
			NewTokenResponse: func(code string) (int, string) {
				if w := "AUTH_CODE"; code != w {
					t.Errorf("code wants %s but %s", w, code)
					return 400, `{"error":"invalid_grant"}`
				}
				return 200, `{"access_token": "ACCESS_TOKEN","token_type": "Bearer","expires_in": 3600,"refresh_token": "REFRESH_TOKEN"}`
			},
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
				status, body, err := openBrowserRequest(url)
				if err != nil {
					cancel()
					t.Errorf("Could not open browser request: %+v", err)
				}
				t.Logf("got response body: %s", body)
				if status != 200 {
					t.Errorf("status wants 200 but %d", status)
				}
				if body != oauth2cli.DefaultLocalServerSuccessHTML {
					t.Errorf("response body did not match")
				}
			case <-ctx.Done():
				t.Errorf("Context done while waiting for opening browser: %+v", ctx.Err())
			}
		}()

		// Start a local server and get a token.
		token, err := oauth2cli.GetToken(ctx, oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Endpoint:     endpoint,
				Scopes:       []string{"email", "profile"},
			},
			LocalServerReadyChan:  openBrowserCh,
			LocalServerMiddleware: loggingMiddleware(t),
		})
		if err != nil {
			t.Errorf("Could not get a token: %+v", err)
			return
		}
		if "ACCESS_TOKEN" != token.AccessToken {
			t.Errorf("AccessToken wants %s but %s", "ACCESS_TOKEN", token.AccessToken)
		}
		if "REFRESH_TOKEN" != token.RefreshToken {
			t.Errorf("RefreshToken wants %s but %s", "REFRESH_TOKEN", token.AccessToken)
		}
	})

	t.Run("ErrorAuthResponse", func(t *testing.T) {
		h := authServerHandler{
			t: t,
			NewAuthResponse: func(scope, state, redirectURI string) string {
				return fmt.Sprintf("%s?error=server_error", redirectURI)
			},
			NewTokenResponse: func(code string) (int, string) {
				return 500, "should not reach here"
			},
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
				status, body, err := openBrowserRequest(url)
				if err != nil {
					cancel()
					t.Errorf("Could not open browser request: %+v", err)
				}
				t.Logf("got response body: %s", body)
				if status != 500 {
					t.Errorf("status wants 500 but %d", status)
				}
			case <-ctx.Done():
				t.Errorf("Context done while waiting for opening browser: %+v", ctx.Err())
			}
		}()

		// Start a local server and get a token.
		_, err := oauth2cli.GetToken(ctx, oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Endpoint:     endpoint,
				Scopes:       []string{"email", "profile"},
			},
			LocalServerReadyChan:  openBrowserCh,
			LocalServerMiddleware: loggingMiddleware(t),
		})
		if err == nil {
			t.Errorf("GetToken wants error but nil")
		}
		t.Logf("expected error: %s", err)
	})

	t.Run("ErrorTokenResponse", func(t *testing.T) {
		h := authServerHandler{
			t: t,
			NewAuthResponse: func(scope, state, redirectURI string) string {
				return fmt.Sprintf("%s?state=%s&code=%s", redirectURI, state, "AUTH_CODE")
			},
			NewTokenResponse: func(code string) (int, string) {
				return 400, `{"error":"invalid_request"}`
			},
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
				status, body, err := openBrowserRequest(url)
				if err != nil {
					cancel()
					t.Errorf("Could not open browser request: %+v", err)
				}
				t.Logf("got response body: %s", body)
				if status != 200 {
					t.Errorf("status wants 200 but %d", status)
				}
				if body != oauth2cli.DefaultLocalServerSuccessHTML {
					t.Errorf("response body did not match")
				}
			case <-ctx.Done():
				t.Errorf("Context done while waiting for opening browser: %+v", ctx.Err())
			}
		}()

		// Start a local server and get a token.
		_, err := oauth2cli.GetToken(ctx, oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Endpoint:     endpoint,
				Scopes:       []string{"email", "profile"},
			},
			LocalServerReadyChan:  openBrowserCh,
			LocalServerMiddleware: loggingMiddleware(t),
		})
		if err == nil {
			t.Errorf("GetToken wants error but nil")
		}
		t.Logf("expected error: %s", err)
	})
}

func loggingMiddleware(t *testing.T) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("oauth2cli: %s %s", r.Method, r.URL)
			h.ServeHTTP(w, r)
		})
	}
}

func openBrowserRequest(url string) (int, string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, "", xerrors.Errorf("could not send a request: %w", err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", xerrors.Errorf("could not read response body: %w", err)
	}
	return resp.StatusCode, string(b), nil
}

type authServerHandler struct {
	t *testing.T

	// This should return a URL with query parameters of authorization response.
	// See https://tools.ietf.org/html/rfc6749#section-4.1.2
	NewAuthResponse func(scope, state, redirectURI string) string

	// This should return a JSON body of access token response or error response.
	// See https://tools.ietf.org/html/rfc6749#section-5.1
	// and https://tools.ietf.org/html/rfc6749#section-5.2
	NewTokenResponse func(code string) (int, string)
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
			return xerrors.New("scope is missing")
		}
		if state == "" {
			return xerrors.New("state is missing")
		}
		if redirectURI == "" {
			return xerrors.New("redirect_uri is missing")
		}
		to := h.NewAuthResponse(scope, state, redirectURI)
		http.Redirect(w, r, to, 302)

	case r.Method == "POST" && r.URL.Path == "/token":
		if err := r.ParseForm(); err != nil {
			return xerrors.Errorf("error while parsing form: %w", err)
		}
		code, redirectURI := r.Form.Get("code"), r.Form.Get("redirect_uri")

		if code == "" {
			return xerrors.New("code is missing")
		}
		if redirectURI == "" {
			return xerrors.New("redirect_uri is missing")
		}
		status, b := h.NewTokenResponse(code)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(b)); err != nil {
			return xerrors.Errorf("error while writing response body: %w", err)
		}

	default:
		http.NotFound(w, r)
	}
	return nil
}
