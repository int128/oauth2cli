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

func TestPKCE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	openBrowserCh := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(openBrowserCh)
		// PKCE test fixture: https://tools.ietf.org/html/rfc7636
		const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		// Start a local server and get a token.
		s := httptest.NewServer(&authserver.Handler{
			T: t,
			NewAuthorizationResponse: func(r authserver.AuthorizationRequest) string {
				if r.Raw.Get("code_challenge_method") != "S256" {
					t.Errorf("code_challenge_method wants S256 but was %s", r.Raw.Get("code_challenge_method"))
				}
				if r.Raw.Get("code_challenge") != codeChallenge {
					t.Errorf("code_challenge wants %s but was %s", codeChallenge, r.Raw.Get("code_challenge"))
				}
				if w := "email profile"; r.Scope != w {
					t.Errorf("scope wants %s but %s", w, r.Scope)
					return fmt.Sprintf("%s?error=invalid_scope", r.RedirectURI)
				}
				return fmt.Sprintf("%s?state=%s&code=%s", r.RedirectURI, r.State, "AUTH_CODE")
			},
			NewTokenResponse: func(r authserver.TokenRequest) (int, string) {
				if r.Raw.Get("code_verifier") != codeVerifier {
					t.Errorf("code_verifier wants %s but was %s", codeVerifier, r.Raw.Get("code_verifier"))
				}
				if w := "AUTH_CODE"; r.Code != w {
					t.Errorf("code wants %s but %s", w, r.Code)
					return 400, invalidGrantResponse
				}
				return 200, validTokenResponse
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
			AuthCodeOptions: []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			},
			TokenRequestOptions: []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam("code_verifier", codeVerifier),
			},
			LocalServerReadyChan:  openBrowserCh,
			LocalServerMiddleware: loggingMiddleware(t),
			Logf:                  t.Logf,
		}
		token, err := oauth2cli.GetToken(ctx, cfg)
		if err != nil {
			t.Errorf("could not get a token: %s", err)
			return
		}
		if "ACCESS_TOKEN" != token.AccessToken {
			t.Errorf("AccessToken wants %s but %s", "ACCESS_TOKEN", token.AccessToken)
		}
		if "REFRESH_TOKEN" != token.RefreshToken {
			t.Errorf("RefreshToken wants %s but %s", "REFRESH_TOKEN", token.AccessToken)
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
