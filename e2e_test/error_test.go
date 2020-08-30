package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/e2e_test/authserver"
	"github.com/int128/oauth2cli/e2e_test/client"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

func TestErrorAuthorizationResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	openBrowserCh := make(chan string)
	var eg errgroup.Group
	eg.Go(func() error {
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
			return errors.New("GetToken wants error but was nil")
		}
		t.Logf("expected error: %s", err)
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
			if status != 500 {
				t.Errorf("status wants 500 but %d", status)
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

func TestErrorTokenResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	openBrowserCh := make(chan string)
	var eg errgroup.Group
	eg.Go(func() error {
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
			return errors.New("GetToken wants error but nil")
		}
		t.Logf("expected error: %s", err)
		return nil
	})
	eg.Go(func() error {
		// Wait for the local server and open a browser request.
		select {
		case to := <-openBrowserCh:
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
