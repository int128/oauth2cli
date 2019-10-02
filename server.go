package oauth2cli

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

func receiveCodeViaLocalServer(ctx context.Context, c *Config) (string, error) {
	state, err := newOAuth2State()
	if err != nil {
		return "", xerrors.Errorf("error while state parameter generation: %w", err)
	}
	listener, err := newLocalhostListener(c.LocalServerAddress, c.LocalServerPort)
	if err != nil {
		return "", xerrors.Errorf("error while starting a local server: %w", err)
	}
	defer listener.Close()

	switch {
	case c.LocalServerCertFile == "" && c.LocalServerKeyFile == "":
	case c.LocalServerCertFile != "" && c.LocalServerKeyFile != "":
		listener.URL.Scheme = "https"
	default:
		return "", xerrors.Errorf("both LocalServerCertFile and LocalServerKeyFile must be set")
	}
	if c.OAuth2Config.RedirectURL == "" {
		c.OAuth2Config.RedirectURL = listener.URL.String()
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
			if err := server.ServeTLS(listener, c.LocalServerCertFile, c.LocalServerKeyFile); err != nil && err != http.ErrServerClosed {
				return xerrors.Errorf("could not start a local TLS server: %w", err)
			}
		} else {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				return xerrors.Errorf("could not start a local server: %w", err)
			}
		}
		return nil
	})
	if c.LocalServerReadyChan != nil {
		c.LocalServerReadyChan <- listener.URL.String()
	}

	if err := eg.Wait(); err != nil {
		return "", xerrors.Errorf("error while authorization: %w", err)
	}
	if resp == nil {
		return "", xerrors.New("no authorization response")
	}
	return resp.code, resp.err
}

func newOAuth2State() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", xerrors.Errorf("error while reading random: %w", err)
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
		return &authorizationResponse{err: xerrors.Errorf("state does not match, wants %s but %s", h.state, state)}
	}
	w.Header().Add("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, h.config.LocalServerSuccessHTML); err != nil {
		http.Error(w, "server error", 500)
		return &authorizationResponse{err: xerrors.Errorf("error while writing response body: %w", err)}
	}
	return &authorizationResponse{code: code}
}

func (h *localServerHandler) handleErrorResponse(w http.ResponseWriter, r *http.Request) *authorizationResponse {
	q := r.URL.Query()
	errorCode, errorDescription := q.Get("error"), q.Get("error_description")

	http.Error(w, "authorization error", 500)
	return &authorizationResponse{err: xerrors.Errorf("authorization error from server: %s %s", errorCode, errorDescription)}
}
