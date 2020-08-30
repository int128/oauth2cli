package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/e2e_test/authserver"
	"github.com/int128/oauth2cli/e2e_test/client"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

const invalidGrantResponse = `{"error":"invalid_grant"}`
const validTokenResponse = `{"access_token": "ACCESS_TOKEN","token_type": "Bearer","expires_in": 3600,"refresh_token": "REFRESH_TOKEN"}`

func TestHappyPath(t *testing.T) {
	cfg := oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			Scopes:       []string{"email", "profile"},
		},
	}
	h := &authserver.Handler{
		T: t,
		NewAuthorizationResponse: func(r authserver.AuthorizationRequest) string {
			if w := "email profile"; r.Scope != w {
				t.Errorf("scope wants %s but %s", w, r.Scope)
				return fmt.Sprintf("%s?error=invalid_scope", r.RedirectURI)
			}
			redirectURIPrefix := "http://localhost:"
			if !strings.HasPrefix(r.RedirectURI, redirectURIPrefix) {
				t.Errorf("redirect_uri wants prefix %s but was %s", redirectURIPrefix, r.RedirectURI)
				return fmt.Sprintf("%s?error=invalid_redirect_uri", r.RedirectURI)
			}
			return fmt.Sprintf("%s?state=%s&code=%s", r.RedirectURI, r.State, "AUTH_CODE")
		},
		NewTokenResponse: func(r authserver.TokenRequest) (int, string) {
			if w := "AUTH_CODE"; r.Code != w {
				t.Errorf("code wants %s but %s", w, r.Code)
				return 400, invalidGrantResponse
			}
			return 200, validTokenResponse
		},
	}
	doAuthCodeFlow(t, cfg, h)
}

func TestRedirectURLHostname(t *testing.T) {
	cfg := oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			Scopes:       []string{"email", "profile"},
		},
		RedirectURLHostname: "127.0.0.1",
	}
	h := &authserver.Handler{
		T: t,
		NewAuthorizationResponse: func(r authserver.AuthorizationRequest) string {
			if w := "email profile"; r.Scope != w {
				t.Errorf("scope wants %s but %s", w, r.Scope)
				return fmt.Sprintf("%s?error=invalid_scope", r.RedirectURI)
			}
			redirectURIPrefix := "http://127.0.0.1:"
			if !strings.HasPrefix(r.RedirectURI, redirectURIPrefix) {
				t.Errorf("redirect_uri wants prefix %s but was %s", redirectURIPrefix, r.RedirectURI)
				return fmt.Sprintf("%s?error=invalid_redirect_uri", r.RedirectURI)
			}
			return fmt.Sprintf("%s?state=%s&code=%s", r.RedirectURI, r.State, "AUTH_CODE")
		},
		NewTokenResponse: func(r authserver.TokenRequest) (int, string) {
			if w := "AUTH_CODE"; r.Code != w {
				t.Errorf("code wants %s but %s", w, r.Code)
				return 400, invalidGrantResponse
			}
			return 200, validTokenResponse
		},
	}
	doAuthCodeFlow(t, cfg, h)
}

func doAuthCodeFlow(t *testing.T, cfg oauth2cli.Config, h *authserver.Handler) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	openBrowserCh := make(chan string)
	var eg errgroup.Group
	eg.Go(func() error {
		defer close(openBrowserCh)
		// Start a local server and get a token.
		s := httptest.NewServer(h)
		defer s.Close()
		cfg.LocalServerReadyChan = openBrowserCh
		cfg.OAuth2Config.Endpoint = oauth2.Endpoint{
			AuthURL:  s.URL + "/auth",
			TokenURL: s.URL + "/token",
		}
		cfg.LocalServerMiddleware = loggingMiddleware(t)
		cfg.Logf = t.Logf
		token, err := oauth2cli.GetToken(ctx, cfg)
		if err != nil {
			return fmt.Errorf("could not get a token: %w", err)
		}
		if "ACCESS_TOKEN" != token.AccessToken {
			t.Errorf("AccessToken wants %s but %s", "ACCESS_TOKEN", token.AccessToken)
		}
		if "REFRESH_TOKEN" != token.RefreshToken {
			t.Errorf("RefreshToken wants %s but %s", "REFRESH_TOKEN", token.AccessToken)
		}
		return nil
	})
	eg.Go(func() error {
		// Wait for the local server and open a browser request.
		select {
		case to, ok := <-openBrowserCh:
			if !ok {
				t.Logf("server already closed")
				return errors.New("server already closed")
			}
			status, body, err := client.Get(to)
			if err != nil {
				return fmt.Errorf("could not open browser request: %w", err)
			}
			t.Logf("got response body: %s", body)
			if status != 200 {
				t.Errorf("status wants 200 but %d", status)
			}
			if body != oauth2cli.DefaultLocalServerSuccessHTML {
				t.Errorf("response body did not match")
			}
			return nil
		case <-ctx.Done():
			return fmt.Errorf("context done while waiting for opening browser: %w", ctx.Err())
		}
	})
	if err := eg.Wait(); err != nil {
		t.Errorf("error: %+v", err)
	}
}

func loggingMiddleware(t *testing.T) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("oauth2cli-local-server: %s %s", r.Method, r.URL)
			h.ServeHTTP(w, r)
		})
	}
}
