package e2e_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/e2e_test/authserver"
	"github.com/int128/oauth2cli/e2e_test/client"
	"golang.org/x/oauth2"
)

func TestTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	openBrowserCh := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(openBrowserCh)
		// Start a local server and get a token.
		testServer := httptest.NewServer(&authserver.Handler{
			TestingT: t,
			NewAuthorizationResponse: func(req authserver.AuthorizationRequest) string {
				if want := "email profile"; req.Scope != want {
					t.Errorf("scope wants %s but %s", want, req.Scope)
					return fmt.Sprintf("%s?error=invalid_scope", req.RedirectURI)
				}
				if !assertRedirectURI(t, req.RedirectURI, "https", "localhost", "") {
					return fmt.Sprintf("%s?error=invalid_redirect_uri", req.RedirectURI)
				}
				return fmt.Sprintf("%s?state=%s&code=%s", req.RedirectURI, req.State, "AUTH_CODE")
			},
			NewTokenResponse: func(req authserver.TokenRequest) (int, string) {
				if want := "AUTH_CODE"; req.Code != want {
					t.Errorf("code wants %s but %s", want, req.Code)
					return 400, invalidGrantResponse
				}
				return 200, validTokenResponse
			},
		})
		defer testServer.Close()
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  testServer.URL + "/auth",
					TokenURL: testServer.URL + "/token",
				},
			},
			LocalServerCertFile:   "testdata/server.crt",
			LocalServerKeyFile:    "testdata/server.key",
			LocalServerReadyChan:  openBrowserCh,
			LocalServerMiddleware: loggingMiddleware(t),
		}
		token, err := oauth2cli.GetToken(ctx, cfg)
		if err != nil {
			t.Errorf("could not get a token: %s", err)
			return
		}
		if token.AccessToken != "ACCESS_TOKEN" {
			t.Errorf("AccessToken wants %s but %s", "ACCESS_TOKEN", token.AccessToken)
		}
		if token.RefreshToken != "REFRESH_TOKEN" {
			t.Errorf("RefreshToken wants %s but %s", "REFRESH_TOKEN", token.RefreshToken)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		toURL, ok := <-openBrowserCh
		if !ok {
			t.Errorf("server already closed")
			return
		}
		client.GetAndVerify(t, toURL, 200, oauth2cli.DefaultLocalServerSuccessHTML)
	}()
	wg.Wait()
}
