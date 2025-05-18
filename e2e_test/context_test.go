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
	"golang.org/x/oauth2"
)

func TestContextCancelOnWaitingForBrowser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 100*time.Millisecond)
	defer cancel()
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
	}
	_, err := oauth2cli.GetToken(ctx, cfg)
	if err == nil {
		t.Errorf("GetToken wants error but was nil")
		return
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err wants DeadlineExceeded but %+v", err)
	}
}

func TestContextCancelOnLocalServerReadyChan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 100*time.Millisecond)
	defer cancel()
	openBrowserCh := make(chan string)
	defer close(openBrowserCh)
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
		LocalServerReadyChan: openBrowserCh}
	_, err := oauth2cli.GetToken(ctx, cfg)
	if err == nil {
		t.Errorf("GetToken wants error but was nil")
		return
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err wants DeadlineExceeded but %+v", err)
	}
}
