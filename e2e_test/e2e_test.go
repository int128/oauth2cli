package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/e2e_test/authserver"
	"github.com/int128/oauth2cli/e2e_test/client"
	"golang.org/x/oauth2"
)

const invalidGrantResponse = `{"error":"invalid_grant"}`
const validTokenResponse = `{"access_token": "ACCESS_TOKEN","token_type": "Bearer","expires_in": 3600,"refresh_token": "REFRESH_TOKEN"}`

func TestHappyPath(t *testing.T) {
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
				if !assertRedirectURI(t, req.RedirectURI, "http", "localhost", "") {
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

func TestRedirectURLHostname(t *testing.T) {
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
				if !assertRedirectURI(t, req.RedirectURI, "http", "127.0.0.1", "") {
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
			RedirectURLHostname:   "127.0.0.1",
			LocalServerReadyChan:  openBrowserCh,
			LocalServerMiddleware: loggingMiddleware(t)}
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

func TestSuccessRedirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	openBrowserCh := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(openBrowserCh)
		// start a local server of oauth2 endpoint
		testServer := httptest.NewServer(&authserver.Handler{
			TestingT: t,
			NewAuthorizationResponse: func(req authserver.AuthorizationRequest) string {
				if want := "email profile"; req.Scope != want {
					t.Errorf("scope wants %s but %s", want, req.Scope)
					return fmt.Sprintf("%s?error=invalid_scope", req.RedirectURI)
				}
				if !assertRedirectURI(t, req.RedirectURI, "http", "localhost", "") {
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
		// start a local server to be redirected
		sr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/success" && r.Method == "GET" {
				_, _ = w.Write([]byte("success page"))
				return
			}
			http.NotFound(w, r)
		}))
		defer sr.Close()
		// get a token
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
			LocalServerReadyChan:  openBrowserCh,
			LocalServerMiddleware: loggingMiddleware(t),
			SuccessRedirectURL:    sr.URL + "/success",
			FailureRedirectURL:    sr.URL + "/failure"}
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
		client.GetAndVerify(t, toURL, 200, "success page")
	}()
	wg.Wait()
}

func assertRedirectURI(t *testing.T, actualURI, scheme, hostname, path string) bool {
	redirect, err := url.Parse(actualURI)
	if err != nil {
		t.Errorf("could not parse redirect_uri: %s", err)
		return false
	}
	if redirect.Scheme != scheme {
		t.Errorf("redirect_uri wants scheme %s but was %s", scheme, redirect.Scheme)
		return false
	}
	if actualHostname := redirect.Hostname(); actualHostname != hostname {
		t.Errorf("redirect_uri wants hostname %s but was %s", hostname, actualHostname)
		return false
	}
	if actualPath := redirect.Path; actualPath != path {
		t.Errorf("redirect_uri wants path %s but was %s", path, actualPath)
		return false
	}
	return true
}

func loggingMiddleware(t *testing.T) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("oauth2cli-local-server: %s %s", r.Method, r.URL)
			h.ServeHTTP(w, r)
		})
	}
}
