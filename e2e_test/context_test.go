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
		Logf: t.Logf,
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
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err wants DeadlineExceeded but %+v", err)
	}
}
