package implicit

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/int128/listener"
	types "github.com/int128/oauth2cli/implicit"
	shared "github.com/int128/oauth2cli/internal"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

// Now returns the current time. Overritten in tests
var Now = time.Now

type AuthorizationResponse struct {
	token *oauth2.Token // non-empty if a valid token is received
	nonce string        // token and id_token should check it the claim "nonce" matches this value
	err   error         // non-nil if an error is received or any error occurs
}

type localServerHandler struct {
	config *types.ServerConfig
	// nonce is a token to protect the user from CSRF attacks. You must
	// always provide a non-empty string and validate that it matches the
	// the state query parameter on your redirect callback.
	// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
	nonce         string
	state         string
	responseCh    chan<- *AuthorizationResponse
	redirectPath  string
	responseTypes []string
}

// query get changed
func (h *localServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fmt.Println(h.redirectPath)
	switch {
	case r.Method == "GET" && r.URL.Path == h.redirectPath && q.Get("error") != "":
		h.responseCh <- h.handleErrorResponse(w, r)
	case r.Method == "POST" && r.URL.Path == h.redirectPath:
		h.responseCh <- h.handleTokenResponse(w, r)
	case r.Method == "GET" && r.URL.Path == h.redirectPath:
		h.handleRawTokenResponse(w, r)
	case r.Method == "GET" && r.URL.Path == "/":
		h.handleIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

// JSPoster posts the url fragment to the redirect path.
const JSPoster = `<html><head><meta http-equiv="content-type" content="text/html; charset=utf-8"/></head><script>
const getSearch = ( str ) => str[ 0 ] === '#' ? str.slice( 1 ) : str;
const content = getSearch(window.location.hash);
fetch("%s?" + content,  {method: "POST"})
	.then(resp => document.body.append("OK"))
	.catch(err => document.body.append(err));
</script></html>
`

func (h *localServerHandler) handleRawTokenResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, JSPoster, h.redirectPath); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}
func (h *localServerHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	url := h.redirectURL()
	http.Redirect(w, r, url, 302)
}

func (h *localServerHandler) handleTokenResponse(w http.ResponseWriter, r *http.Request) *AuthorizationResponse {
	vals := r.URL.Query()
	token := &oauth2.Token{
		AccessToken: vals.Get("access_token"),
		TokenType:   vals.Get("token_type"),
	}

	if state := vals.Get("state"); state != h.state {
		http.Error(w, "server error", 500)
		return &AuthorizationResponse{err: xerrors.Errorf("state does not match, wants %q but got %q", h.state, state)}
	}

	if h.hasTokenResponse() {
		if token.AccessToken = vals.Get("access_token"); token.AccessToken == "" {
			http.Error(w, "server error", 500)
			return &AuthorizationResponse{err: xerrors.Errorf("access_token missing in authentication response when requesting token")}
		}
		if token.TokenType = vals.Get("token_type"); token.TokenType == "" {
			http.Error(w, "server error", 500)
			return &AuthorizationResponse{err: xerrors.Errorf("token_type missing in authentication response when requesting token")}
		}
	}

	if h.hasIDTokenResponse() {
		idToken := vals.Get("id_token")
		if idToken == "" {
			http.Error(w, "server error", 500)
			return &AuthorizationResponse{err: xerrors.Errorf("id_token missing in authentication response when requesting id_token")}
		}
		vals.Set("id_token", idToken)
	}

	e := vals.Get("expires_in")
	expires, _ := strconv.Atoi(e)
	if expires != 0 {
		token.Expiry = Now().Add(time.Duration(expires) * time.Second)
	}
	token = token.WithExtra(vals)

	w.Header().Add("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, h.config.LocalServerSuccessHTML); err != nil {
		http.Error(w, "server error", 500)
		return &AuthorizationResponse{err: xerrors.Errorf("error while writing response body: %w", err)}
	}
	return &AuthorizationResponse{token: token, nonce: h.nonce}
}

func (h *localServerHandler) handleErrorResponse(w http.ResponseWriter, r *http.Request) *AuthorizationResponse {
	q := r.URL.Query()
	errorCode, errorDescription := q.Get("error"), q.Get("error_description")

	http.Error(w, "authorization error", 500)
	return &AuthorizationResponse{err: xerrors.Errorf("authorization error from server: %s %s", errorCode, errorDescription)}
}

func (h *localServerHandler) hasResponse(seek string) bool {
	for _, rr := range h.responseTypes {
		if rr == seek {
			return true
		}
	}
	return false
}

func (h *localServerHandler) hasIDTokenResponse() bool {
	return h.hasResponse("id_token")
}

func (h *localServerHandler) hasTokenResponse() bool {
	return h.hasResponse("token")
}

// URL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
func (h *localServerHandler) redirectURL() string {
	var buf bytes.Buffer

	c := h.config.Config
	buf.WriteString(c.AuthURL)

	v := url.Values{
		"response_type": {strings.Join(h.responseTypes, " ")},
		"client_id":     {c.ClientID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}

	v.Set("state", h.state)

	if h.nonce != "" {
		v.Set("nonce", h.nonce)
	}
	if strings.Contains(c.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

func ReceiveTokenViaLocalServer(ctx context.Context, c *types.ServerConfig, responseTypes []string) (token *oauth2.Token, nonce string, err error) {
	state, err := shared.NewOAuth2State()
	if err != nil {
		return nil, "", xerrors.Errorf("error while state parameter generation: %w", err)
	}
	nonce, err = shared.NewOAuth2State()
	if err != nil {
		return nil, "", xerrors.Errorf("error while nonce parameter generation: %w", err)
	}
	l, err := listener.New(shared.ExpandAddresses(c.LocalServerAddress, c.LocalServerPort))
	if err != nil {
		return nil, "", xerrors.Errorf("error while starting a local server: %w", err)
	}
	defer l.Close()

	if c.LocalServerCertFile == "" || c.LocalServerKeyFile == "" {
		return nil, "", xerrors.Errorf("LocalServerCertFile and LocalServerKeyFile must be set when using implicit flow")
	}
	var redirectPath = "implicit"

	l.URL.Scheme = "https"

	if c.Config.RedirectURL == "" {
		l.URL.Path = "implicit"
		c.Config.RedirectURL = l.URL.String()
	} else {
		rd, err := url.Parse(c.Config.RedirectURL)
		if err != nil {
			return nil, "", xerrors.Errorf("redirect URL must be a valid URL: %w", err)
		}
		if rd.Path == "" || len(rd.Path) == 1 {
			return nil, "", xerrors.Errorf("redirect URL path must not be empty")
		}
		// rd.ResolveReference()
		redirectPath = rd.Path

		if rd.Scheme != "https" {
			return nil, "", xerrors.Errorf("redirect URL scheme must be https")
		}
	}

	respCh := make(chan *AuthorizationResponse)
	server := http.Server{
		Handler: c.LocalServerMiddleware(&localServerHandler{
			config:        c,
			nonce:         nonce,
			state:         state,
			responseCh:    respCh,
			redirectPath:  redirectPath,
			responseTypes: responseTypes,
		}),
	}
	var resp *AuthorizationResponse
	var eg errgroup.Group
	eg.Go(func() error {
		for {
			select {
			case received, ok := <-respCh:
				if !ok {
					return nil // channel is closed (after the server is stopped)
				}
				if resp == nil {
					resp = received // pick only the first response
				}
				if err := server.Shutdown(ctx); err != nil {
					return xerrors.Errorf("could not shutdown the local server: %w", err)
				}
			case <-ctx.Done():
				if err := server.Shutdown(ctx); err != nil {
					return xerrors.Errorf("could not shutdown the local server: %w", err)
				}
				return xerrors.Errorf("context done while waiting for authorization response: %w", ctx.Err())
			}
		}
	})
	eg.Go(func() error {
		defer close(respCh)
		if c.LocalServerCertFile != "" && c.LocalServerKeyFile != "" {
			if err := server.ServeTLS(l, c.LocalServerCertFile, c.LocalServerKeyFile); err != nil && err != http.ErrServerClosed {
				return xerrors.Errorf("could not start a local TLS server: %w", err)
			}
		} else {
			if err := server.Serve(l); err != nil && err != http.ErrServerClosed {
				return xerrors.Errorf("could not start a local server: %w", err)
			}
		}
		return nil
	})

	if c.LocalServerReadyChan != nil {
		c.LocalServerReadyChan <- l.URL.String()
	}

	if err := eg.Wait(); err != nil {
		return nil, "", xerrors.Errorf("error while authorization: %w", err)
	}
	if resp == nil {
		return nil, "", xerrors.New("no authorization response")
	}
	ctx.Done()
	return resp.token, resp.nonce, resp.err
}
