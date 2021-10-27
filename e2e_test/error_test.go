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
		s := httptest.NewServer(&authserver.Handler{
			T: t,
			NewAuthorizationResponse: func(r authserver.AuthorizationRequest) string {
				return fmt.Sprintf("%s?error=server_error", r.RedirectURI)
			},
			NewTokenResponse: func(r authserver.TokenRequest) (int, string) {
				return 500, "should not reach here"
			},
		})
		defer s.Close()
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  s.URL + "/auth",
					TokenURL: s.URL + "/token",
				},
			},
			LocalServerReadyChan: openBrowserCh,
			Logf:                 t.Logf,
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
	openBrowserCh := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(openBrowserCh)
		// start a local server of oauth2 endpoint
		s := httptest.NewServer(&authserver.Handler{
			T: t,
			NewAuthorizationResponse: func(r authserver.AuthorizationRequest) string {
				return fmt.Sprintf("%s?error=server_error", r.RedirectURI)
			},
			NewTokenResponse: func(r authserver.TokenRequest) (int, string) {
				return 500, "should not reach here"
			},
		})
		defer s.Close()
		// start a local server to be redirected
		sr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/failure" && r.Method == "GET" {
				_, _ = w.Write([]byte("failure page"))
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
					AuthURL:  s.URL + "/auth",
					TokenURL: s.URL + "/token",
				},
			},
			LocalServerReadyChan: openBrowserCh,
			SuccessRedirectURL:   sr.URL + "/success",
			FailureRedirectURL:   sr.URL + "/failure",
			Logf:                 t.Logf,
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
		s := httptest.NewServer(&authserver.Handler{
			T: t,
			NewAuthorizationResponse: func(r authserver.AuthorizationRequest) string {
				return fmt.Sprintf("%s?state=%s&code=%s", r.RedirectURI, r.State, "AUTH_CODE")
			},
			NewTokenResponse: func(r authserver.TokenRequest) (int, string) {
				return 400, `{"error":"invalid_request"}`
			},
		})
		defer s.Close()
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  s.URL + "/auth",
					TokenURL: s.URL + "/token",
				},
			},
			LocalServerReadyChan: openBrowserCh,
			Logf:                 t.Logf,
		}
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
