package oauth2cli

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

func receiveCodeViaLocalServer(ctx context.Context, c *Config) (string, error) {
	state, err := newOAuth2State()
	if err != nil {
		return "", errors.Wrapf(err, "error while state parameter generation")
	}
	listener, err := newLocalhostListener(c.LocalServerPort)
	if err != nil {
		return "", errors.Wrapf(err, "error while starting a local server")
	}
	defer listener.Close()
	if c.OAuth2Config.RedirectURL == "" {
		c.OAuth2Config.RedirectURL = listener.URL
	}

	if c.ShowLocalServerURL != nil {
		c.ShowLocalServerURL(listener.URL)
	}
	if !c.SkipOpenBrowser {
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = browser.OpenURL(listener.URL)
		}()
	}

	respCh := make(chan *authorizationResponse)
	server := http.Server{
		Handler: c.LocalServerMiddleware(&localServerHandler{
			config:     c,
			state:      state,
			responseCh: respCh,
		}),
	}
	var resp *authorizationResponse
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
					return errors.Wrapf(err, "could not shutdown the local server")
				}
			case <-ctx.Done():
				if err := server.Shutdown(ctx); err != nil {
					return errors.Wrapf(err, "could not shutdown the local server")
				}
				return errors.Wrapf(ctx.Err(), "context done while waiting for authorization response")
			}
		}
	})
	eg.Go(func() error {
		defer close(respCh)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			return errors.Wrapf(err, "could not start a local server")
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return "", errors.WithStack(err)
	}
	if resp == nil {
		return "", errors.Errorf("no authorization response")
	}
	return resp.code, resp.err
}

func newOAuth2State() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", errors.Wrapf(err, "error while reading random")
	}
	return fmt.Sprintf("%x", n), nil
}

type authorizationResponse struct {
	code string // non-empty if a valid code is received
	err  error  // non-nil if an error is received or any error occurs
}

type localServerHandler struct {
	config     *Config
	state      string
	responseCh chan<- *authorizationResponse
}

func (h *localServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && r.URL.Path == "/" && q.Get("error") != "":
		h.responseCh <- h.handleErrorResponse(w, r)
	case r.Method == "GET" && r.URL.Path == "/" && q.Get("code") != "":
		h.responseCh <- h.handleCodeResponse(w, r)
	case r.Method == "GET" && r.URL.Path == "/":
		h.handleIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *localServerHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	url := h.config.OAuth2Config.AuthCodeURL(h.state, h.config.AuthCodeOptions...)
	http.Redirect(w, r, url, 302)
}

func (h *localServerHandler) handleCodeResponse(w http.ResponseWriter, r *http.Request) *authorizationResponse {
	q := r.URL.Query()
	code, state := q.Get("code"), q.Get("state")

	if state != h.state {
		http.Error(w, "authorization error", 500)
		return &authorizationResponse{err: errors.Errorf("state does not match, wants %s but %s", h.state, state)}
	}
	w.Header().Add("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, h.config.LocalServerSuccessHTML); err != nil {
		http.Error(w, "server error", 500)
		return &authorizationResponse{err: errors.Wrapf(err, "error while writing response body")}
	}
	return &authorizationResponse{code: code}
}

func (h *localServerHandler) handleErrorResponse(w http.ResponseWriter, r *http.Request) *authorizationResponse {
	q := r.URL.Query()
	errorCode, errorDescription := q.Get("error"), q.Get("error_description")

	http.Error(w, "authorization error", 500)
	return &authorizationResponse{err: errors.Errorf("authorization error from server: %s %s", errorCode, errorDescription)}
}
