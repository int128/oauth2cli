package oauth2cli_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

func TestGetToken(t *testing.T) {
	const invalidGrantResponse = `{"error":"invalid_grant"}`
	const validTokenResponse = `{"access_token": "ACCESS_TOKEN","token_type": "Bearer","expires_in": 3600,"refresh_token": "REFRESH_TOKEN"}`

	t.Run("NoTLS", func(t *testing.T) {
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
			},
			LocalServerMiddleware: loggingMiddleware(t),
		}
		h := &authServerHandler{
			t: t,
			NewAuthorizationResponse: func(r authorizationRequest) string {
				if w := "email profile"; r.scope != w {
					t.Errorf("scope wants %s but %s", w, r.scope)
					return fmt.Sprintf("%s?error=invalid_scope", r.redirectURI)
				}
				return fmt.Sprintf("%s?state=%s&code=%s", r.redirectURI, r.state, "AUTH_CODE")
			},
			NewTokenResponse: func(r tokenRequest) (int, string) {
				if w := "AUTH_CODE"; r.code != w {
					t.Errorf("code wants %s but %s", w, r.code)
					return 400, invalidGrantResponse
				}
				return 200, validTokenResponse
			},
		}
		successfulTest(t, cfg, h)
	})

	t.Run("TLS", func(t *testing.T) {
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
			},
			LocalServerCertFile:   "testdata/cert.pem",
			LocalServerKeyFile:    "testdata/cert-key.pem",
			LocalServerMiddleware: loggingMiddleware(t),
		}
		h := &authServerHandler{
			t: t,
			NewAuthorizationResponse: func(r authorizationRequest) string {
				if w := "email profile"; r.scope != w {
					t.Errorf("scope wants %s but %s", w, r.scope)
					return fmt.Sprintf("%s?error=invalid_scope", r.redirectURI)
				}
				if !strings.HasPrefix(r.redirectURI, "https://") {
					t.Errorf("redirect_uri must start with https:// when using TLS config %s", r.redirectURI)
					return fmt.Sprintf("%s?error=invalid_redirect_uri", r.redirectURI)
				}
				return fmt.Sprintf("%s?state=%s&code=%s", r.redirectURI, r.state, "AUTH_CODE")
			},
			NewTokenResponse: func(r tokenRequest) (int, string) {
				if w := "AUTH_CODE"; r.code != w {
					t.Errorf("code wants %s but %s", w, r.code)
					return 400, invalidGrantResponse
				}
				return 200, validTokenResponse
			},
		}
		successfulTest(t, cfg, h)
	})

	t.Run("PKCE", func(t *testing.T) {
		// https://tools.ietf.org/html/rfc7636
		const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
			},
			AuthCodeOptions: []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			},
			TokenRequestOptions: []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam("code_verifier", codeVerifier),
			},
			LocalServerMiddleware: loggingMiddleware(t),
		}
		h := &authServerHandler{
			t: t,
			NewAuthorizationResponse: func(r authorizationRequest) string {
				if r.raw.Get("code_challenge_method") != "S256" {
					t.Errorf("code_challenge_method wants S256 but was %s", r.raw.Get("code_challenge_method"))
				}
				if r.raw.Get("code_challenge") != codeChallenge {
					t.Errorf("code_challenge wants %s but was %s", codeChallenge, r.raw.Get("code_challenge"))
				}
				if w := "email profile"; r.scope != w {
					t.Errorf("scope wants %s but %s", w, r.scope)
					return fmt.Sprintf("%s?error=invalid_scope", r.redirectURI)
				}
				return fmt.Sprintf("%s?state=%s&code=%s", r.redirectURI, r.state, "AUTH_CODE")
			},
			NewTokenResponse: func(r tokenRequest) (int, string) {
				if r.raw.Get("code_verifier") != codeVerifier {
					t.Errorf("code_verifier wants %s but was %s", codeVerifier, r.raw.Get("code_verifier"))
				}
				if w := "AUTH_CODE"; r.code != w {
					t.Errorf("code wants %s but %s", w, r.code)
					return 400, invalidGrantResponse
				}
				return 200, validTokenResponse
			},
		}
		successfulTest(t, cfg, h)
	})

	t.Run("ErrorAuthorizationResponse", func(t *testing.T) {
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
			},
			LocalServerMiddleware: loggingMiddleware(t),
		}
		errorAuthorizationResponseTest(t, cfg)
	})

	t.Run("ErrorTokenResponse", func(t *testing.T) {
		cfg := oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				Scopes:       []string{"email", "profile"},
			},
			LocalServerMiddleware: loggingMiddleware(t),
		}
		errorTokenResponseTest(t, cfg)
	})
}

func successfulTest(t *testing.T, cfg oauth2cli.Config, h *authServerHandler) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	s := httptest.NewServer(h)
	defer s.Close()
	openBrowserCh := make(chan string)
	defer close(openBrowserCh)

	cfg.LocalServerReadyChan = openBrowserCh
	cfg.OAuth2Config.Endpoint = oauth2.Endpoint{
		AuthURL:  s.URL + "/auth",
		TokenURL: s.URL + "/token",
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		// Wait for the local server and open a browser request.
		select {
		case to := <-openBrowserCh:
			status, body, err := openBrowserRequest(to)
			if err != nil {
				return xerrors.Errorf("could not open browser request: %w", err)
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
			return xerrors.Errorf("context done while waiting for opening browser: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		// Start a local server and get a token.
		token, err := oauth2cli.GetToken(ctx, cfg)
		if err != nil {
			return xerrors.Errorf("could not get a token: %w", err)
		}
		if "ACCESS_TOKEN" != token.AccessToken {
			t.Errorf("AccessToken wants %s but %s", "ACCESS_TOKEN", token.AccessToken)
		}
		if "REFRESH_TOKEN" != token.RefreshToken {
			t.Errorf("RefreshToken wants %s but %s", "REFRESH_TOKEN", token.AccessToken)
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		t.Errorf("error: %+v", err)
	}

}

func errorAuthorizationResponseTest(t *testing.T, cfg oauth2cli.Config) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	h := authServerHandler{
		t: t,
		NewAuthorizationResponse: func(r authorizationRequest) string {
			return fmt.Sprintf("%s?error=server_error", r.redirectURI)
		},
		NewTokenResponse: func(r tokenRequest) (int, string) {
			return 500, "should not reach here"
		},
	}
	s := httptest.NewServer(&h)
	defer s.Close()
	openBrowserCh := make(chan string)
	defer close(openBrowserCh)
	cfg.LocalServerReadyChan = openBrowserCh
	cfg.OAuth2Config.Endpoint = oauth2.Endpoint{
		AuthURL:  s.URL + "/auth",
		TokenURL: s.URL + "/token",
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		// Wait for the local server and open a browser request.
		select {
		case to := <-openBrowserCh:
			status, body, err := openBrowserRequest(to)
			if err != nil {
				return xerrors.Errorf("could not open browser request: %w", err)
			}
			t.Logf("got response body: %s", body)
			if status != 500 {
				t.Errorf("status wants 500 but %d", status)
			}
			return nil
		case <-ctx.Done():
			return xerrors.Errorf("context done while waiting for opening browser: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		// Start a local server and get a token.
		_, err := oauth2cli.GetToken(ctx, cfg)
		if err == nil {
			return xerrors.New("GetToken wants error but was nil")
		}
		t.Logf("expected error: %s", err)
		return nil
	})
	if err := eg.Wait(); err != nil {
		t.Errorf("error: %+v", err)
	}
}

func errorTokenResponseTest(t *testing.T, cfg oauth2cli.Config) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	h := authServerHandler{
		t: t,
		NewAuthorizationResponse: func(r authorizationRequest) string {
			return fmt.Sprintf("%s?state=%s&code=%s", r.redirectURI, r.state, "AUTH_CODE")
		},
		NewTokenResponse: func(r tokenRequest) (int, string) {
			return 400, `{"error":"invalid_request"}`
		},
	}
	s := httptest.NewServer(&h)
	defer s.Close()
	openBrowserCh := make(chan string)
	defer close(openBrowserCh)
	cfg.LocalServerReadyChan = openBrowserCh
	cfg.OAuth2Config.Endpoint = oauth2.Endpoint{
		AuthURL:  s.URL + "/auth",
		TokenURL: s.URL + "/token",
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		// Wait for the local server and open a browser request.
		select {
		case to := <-openBrowserCh:
			status, body, err := openBrowserRequest(to)
			if err != nil {
				return xerrors.Errorf("could not open browser request: %w", err)
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
			return xerrors.Errorf("context done while waiting for opening browser: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		// Start a local server and get a token.
		_, err := oauth2cli.GetToken(ctx, cfg)
		if err == nil {
			return xerrors.New("GetToken wants error but nil")
		}
		t.Logf("expected error: %s", err)
		return nil
	})
	if err := eg.Wait(); err != nil {
		t.Errorf("error: %+v", err)
	}
}

func loggingMiddleware(t *testing.T) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("oauth2cli: %s %s", r.Method, r.URL)
			h.ServeHTTP(w, r)
		})
	}
}

func openBrowserRequest(url string) (int, string, error) {
	certPool := x509.NewCertPool()
	data, err := ioutil.ReadFile("testdata/ca.pem")
	if err != nil {
		return 0, "", xerrors.Errorf("could not read certificate authority: %w", err)
	}
	if !certPool.AppendCertsFromPEM(data) {
		return 0, "", fmt.Errorf("could not append certificate data")
	}

	// we add our custom CA, otherwise the client will throw an invalid certificate error.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", xerrors.Errorf("could not send a request: %w", err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", xerrors.Errorf("could not read response body: %w", err)
	}
	return resp.StatusCode, string(b), nil
}

type authorizationRequest struct {
	scope       string
	state       string
	redirectURI string
	raw         url.Values
}

type tokenRequest struct {
	code string
	raw  url.Values
}

type authServerHandler struct {
	t *testing.T

	// This should return a URL with query parameters of authorization response.
	// See https://tools.ietf.org/html/rfc6749#section-4.1.2
	NewAuthorizationResponse func(r authorizationRequest) string

	// This should return a JSON body of access token response or error response.
	// See https://tools.ietf.org/html/rfc6749#section-5.1
	// and https://tools.ietf.org/html/rfc6749#section-5.2
	NewTokenResponse func(r tokenRequest) (int, string)
}

func (h *authServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.t.Logf("authServer: %s %s", r.Method, r.RequestURI)
	if err := h.serveHTTP(w, r); err != nil {
		h.t.Errorf("authServerHandler error: %s", err)
		http.Error(w, err.Error(), 500)
	}
}

func (h *authServerHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	switch {
	case r.Method == "GET" && r.URL.Path == "/auth":
		q := r.URL.Query()
		scope, state, redirectURI := q.Get("scope"), q.Get("state"), q.Get("redirect_uri")
		if scope == "" {
			return xerrors.New("scope is missing")
		}
		if state == "" {
			return xerrors.New("state is missing")
		}
		if redirectURI == "" {
			return xerrors.New("redirect_uri is missing")
		}
		to := h.NewAuthorizationResponse(authorizationRequest{
			scope:       scope,
			state:       state,
			redirectURI: redirectURI,
			raw:         q,
		})
		http.Redirect(w, r, to, 302)

	case r.Method == "POST" && r.URL.Path == "/token":
		if err := r.ParseForm(); err != nil {
			return xerrors.Errorf("error while parsing form: %w", err)
		}
		code, redirectURI := r.Form.Get("code"), r.Form.Get("redirect_uri")
		if code == "" {
			return xerrors.New("code is missing")
		}
		if redirectURI == "" {
			return xerrors.New("redirect_uri is missing")
		}
		status, b := h.NewTokenResponse(tokenRequest{
			code: code,
			raw:  r.Form,
		})
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(b)); err != nil {
			return xerrors.Errorf("error while writing response body: %w", err)
		}

	default:
		http.NotFound(w, r)
	}
	return nil
}
