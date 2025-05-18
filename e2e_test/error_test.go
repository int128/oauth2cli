package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/e2e_test/authserver"
	"github.com/int128/oauth2cli/e2e_test/client"
	"golang.org/x/oauth2"
)

func TestErrorAuthorizationResponse(t *testing.T) {
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
				return fmt.Sprintf("%s?error=server_error", req.RedirectURI)
			},
			NewTokenResponse: func(req authserver.TokenRequest) (int, string) {
				return 500, "should not reach here"
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
			LocalServerReadyChan: openBrowserCh,
		}
		_, err := oauth2cli.GetToken(ctx, cfg)
		if err == nil {
			t.Errorf("GetToken wants error but was nil")
			return
		}
		t.Logf("expected error: %s", err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		toURL, ok := <-openBrowserCh
		if !ok {
			t.Errorf("server already closed")
			return
		}
		client.GetAndVerify(t, toURL, 500, "authorization error\n")
	}()
	wg.Wait()
}

func TestFailureRedirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()

	// start a local server of oauth2 endpoint
	authzServer := httptest.NewServer(&authserver.Handler{
		TestingT: t,
		NewAuthorizationResponse: func(req authserver.AuthorizationRequest) string {
			return fmt.Sprintf("%s?error=server_error", req.RedirectURI)
		},
		NewTokenResponse: func(req authserver.TokenRequest) (int, string) {
			return 500, "should not reach here"
		},
	})
	defer authzServer.Close()

	// start a local server to be redirected
	pageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failure" && r.Method == "GET" {
			_, _ = w.Write([]byte("failure page"))
			return
		}
		http.NotFound(w, r)
	}))
	defer pageServer.Close()

	openBrowserCh := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(openBrowserCh)
		// get a token
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  authzServer.URL + "/auth",
					TokenURL: authzServer.URL + "/token",
				},
			},
			LocalServerReadyChan: openBrowserCh,
			SuccessRedirectURL:   pageServer.URL + "/success",
			FailureRedirectURL:   pageServer.URL + "/failure"}
		_, err := oauth2cli.GetToken(ctx, cfg)
		if err == nil {
			t.Errorf("GetToken wants error but was nil")
			return
		}
		t.Logf("expected error: %s", err)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		toURL, ok := <-openBrowserCh
		if !ok {
			t.Errorf("server already closed")
			return
		}
		client.GetAndVerify(t, toURL, 200, "failure page")
	}()
	wg.Wait()
}

func TestErrorTokenResponse(t *testing.T) {
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
				return fmt.Sprintf("%s?state=%s&code=%s", req.RedirectURI, req.State, "AUTH_CODE")
			},
			NewTokenResponse: func(req authserver.TokenRequest) (int, string) {
				return 400, `{"error":"invalid_request"}`
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
			LocalServerReadyChan: openBrowserCh}
		_, err := oauth2cli.GetToken(ctx, cfg)
		if err == nil {
			t.Errorf("GetToken wants error but nil")
			return
		}
		t.Logf("expected error: %s", err)
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
