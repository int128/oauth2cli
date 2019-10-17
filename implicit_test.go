package oauth2cli_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/implicit"
	internal_implicit "github.com/int128/oauth2cli/internal/implicit"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

func init() {
	// for tests we want to have a stable time
	internal_implicit.Now = func() time.Time { return time.Time{} }
}

func TestGetTokenImplicitly(t *testing.T) {
	cfg := &implicit.ServerConfig{
		Config: implicit.Config{
			ClientID: "YOUR_CLIENT_ID",
			Scopes:   []string{"email", "profile"},
		},
		LocalServerCertFile:   "testdata/cert.pem",
		LocalServerKeyFile:    "testdata/cert-key.pem",
		LocalServerMiddleware: loggingMiddleware(t),
	}

	t.Run("Success", func(t *testing.T) { successfulTokenImplicitTest(t, cfg) })
}

type implicitAuthServerHandler struct {
	t               *testing.T
	NewAuthResponse func(scope, state, nonce, redirectURI string) string
}

func (h *implicitAuthServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serveHTTP(w, r); err != nil {
		h.t.Errorf("authServerHandler error: %s", err)
		http.Error(w, err.Error(), 500)
	}
}

func (h *implicitAuthServerHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	switch {
	case r.Method == "GET" && r.URL.Path == "/auth":
		q := r.URL.Query()
		scope, nonce, state, redirectURI := q.Get("scope"), q.Get("nonce"), q.Get("state"), q.Get("redirect_uri")

		if scope == "" {
			return xerrors.New("scope is missing")
		}
		if state == "" {
			return xerrors.New("state is missing")
		}
		if redirectURI == "" {
			return xerrors.New("redirect_uri is missing")
		}
		to := h.NewAuthResponse(scope, nonce, state, redirectURI)
		http.Redirect(w, r, to, http.StatusFound)
	default:
		http.NotFound(w, r)
	}
	return nil
}

func successfulTokenImplicitTest(t *testing.T, cfg *implicit.ServerConfig) {
	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Hour)
	defer cancel()
	h := implicitAuthServerHandler{
		t: t,
		NewAuthResponse: func(scope, nonce, state, redirectURI string) string {
			if w := "email profile"; scope != w {
				t.Errorf("scope wants %s but %s", w, scope)
				return fmt.Sprintf("%s?error=invalid_scope", redirectURI)
			}
			if cfg.LocalServerCertFile != "" && !strings.HasPrefix(redirectURI, "https://") {
				t.Errorf("redirect_uri must start with https:// when using TLS config %s", redirectURI)
				return fmt.Sprintf("%s?error=invalid_redirect_uri", redirectURI)
			}
			return fmt.Sprintf("%s#access_token=ACCESS_TOKEN&state=%s&token_type=bearer&expires_in=3333", redirectURI, state)
		},
	}
	s := httptest.NewServer(&h)

	defer s.Close()

	openBrowserCh := make(chan string)
	defer close(openBrowserCh)

	cfg.LocalServerReadyChan = openBrowserCh

	p := randomPort()
	cfg.LocalServerPort = []int{p}
	cfg.Config.AuthURL = s.URL + "/auth"
	cfg.Config.RedirectURL = fmt.Sprintf("https://localhost:%d/oauth2/implicit/callback", p)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		// Wait for the local server and open a browser request.
		select {
		case url := <-openBrowserCh:
			resp, body, err := openBrowserRequest(ctx, url)
			if err != nil {
				return xerrors.Errorf("could not open browser request: %w", err)
			}
			if resp.StatusCode != 200 {
				return xerrors.Errorf("status wants 200 but %d", resp.StatusCode)
			}
			if expected := fmt.Sprintf(internal_implicit.JSPoster, "/oauth2/implicit/callback"); body != expected {
				return xerrors.Errorf("response body did not match, want:\n%s\nbut was:\n%s", expected, body)
			}
			resp, err = postFragment(ctx, cfg.Config.RedirectURL, resp)
			if resp.StatusCode != 200 {
				return xerrors.Errorf("status wants 200 but %d", resp.StatusCode)
			}
			return err
		case <-ctx.Done():
			return xerrors.Errorf("context done while waiting for opening browser: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		// Start a local server and get a token.
		token, err := oauth2cli.GetTokenImplicitly(ctx, cfg)
		if err != nil {
			return xerrors.Errorf("could not get a token: %w", err)
		}
		if token.AccessToken != "ACCESS_TOKEN" {
			return xerrors.Errorf("AccessToken wants %q but %q", "ACCESS_TOKEN", token.AccessToken)
		}
		if token.Type() != "Bearer" {
			return xerrors.Errorf("TokenType should be %q but %q", "Bearer", token.Type())
		}
		if token.RefreshToken != "" {
			return xerrors.Errorf("RefreshToken should not be set but it is %q", token.RefreshToken)
		}

		expectedTime := (time.Time{}).Add(time.Second * 3333)
		if token.Expiry != expectedTime {
			return xerrors.Errorf("Expiry wants %v but was %v", expectedTime, token.Expiry)
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		t.Errorf("error: %+v", err)
	}
}

// returns a random port between 1024 and 32767
func randomPort() int {
	return 1024 + rand.New(rand.NewSource(time.Now().UnixNano())).Intn(31744)
}

func postFragment(ctx context.Context, postURL string, r *http.Response) (*http.Response, error) {
	c, err := client()
	if err != nil {
		return nil, xerrors.Errorf("could not create client: %w", err)
	}
	locationURL, err := url.Parse(r.Request.Response.Header.Get("Location"))
	if err != nil {
		return nil, xerrors.Errorf("could not paste location url: %w", err)
	}
	p, err := url.Parse(postURL)
	if err != nil {
		return nil, xerrors.Errorf("could not parse postURL: %w", err)
	}

	p.RawQuery = locationURL.Fragment

	pr, err := http.NewRequestWithContext(ctx, "POST", p.String(), nil)
	if err != nil {
		return nil, xerrors.Errorf("could not create post request: %w", err)
	}
	return c.Do(pr)
}

func client() (*http.Client, error) {
	certPool := x509.NewCertPool()
	data, err := ioutil.ReadFile("testdata/ca.pem")
	if err != nil {
		return nil, xerrors.Errorf("could not read certificate authority: %w", err)
	}
	if !certPool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("could not append certificate data")
	}

	// we add our custom CA, otherwise the client will throw an invalid certificate error.
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}}, nil
}
