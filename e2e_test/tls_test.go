package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/e2e_test/authserver"
	"golang.org/x/oauth2"
)

func TestTLS(t *testing.T) {
	cfg := oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			Scopes:       []string{"email", "profile"},
		},
		LocalServerCertFile: "testdata/cert.pem",
		LocalServerKeyFile:  "testdata/cert-key.pem",
	}
	h := &authserver.Handler{
		T: t,
		NewAuthorizationResponse: func(r authserver.AuthorizationRequest) string {
			if w := "email profile"; r.Scope != w {
				t.Errorf("scope wants %s but %s", w, r.Scope)
				return fmt.Sprintf("%s?error=invalid_scope", r.RedirectURI)
			}
			redirectURIPrefix := "https://localhost:"
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
