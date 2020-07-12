package oauth2cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/int128/listener"
	"golang.org/x/sync/errgroup"
)

func receiveCodeViaLocalServer(ctx context.Context, c *Config) (string, error) {
	l, err := listener.New(c.LocalServerBindAddress)
	if err != nil {
		return "", fmt.Errorf("could not start a local server: %w", err)
	}
	defer l.Close()
	c.OAuth2Config.RedirectURL = computeRedirectURL(l, c)

	respCh := make(chan *authorizationResponse)
	server := http.Server{
		Handler: c.LocalServerMiddleware(&localServerHandler{
			config:     c,
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
					c.Logf("oauth2cli: response channel has been closed")
					return nil // channel is closed (after the server is stopped)
				}
				if resp == nil {
					resp = received // pick only the first response
				}
				c.Logf("oauth2cli: shutting down the server at %s", l.Addr())
				if err := server.Shutdown(ctx); err != nil {
					return fmt.Errorf("could not shutdown the local server: %w", err)
				}
			case <-ctx.Done():
				c.Logf("oauth2cli: context cancelled: %s", ctx.Err())
				c.Logf("oauth2cli: shutting down the server at %s", l.Addr())
				if err := server.Shutdown(ctx); err != nil {
					return fmt.Errorf("could not shutdown the local server: %w", err)
				}
				return fmt.Errorf("context cancelled while waiting for authorization response: %w", ctx.Err())
			}
		}
	})
	eg.Go(func() error {
		defer close(respCh)
		if c.LocalServerCertFile != "" && c.LocalServerKeyFile != "" {
			c.Logf("oauth2cli: starting HTTPS server at %s", l.Addr())
			if err := server.ServeTLS(l, c.LocalServerCertFile, c.LocalServerKeyFile); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("could not start HTTPS server: %w", err)
			}
			c.Logf("oauth2cli: stopped HTTPS server at %s", l.Addr())
		} else {
			c.Logf("oauth2cli: starting HTTP server at %s", l.Addr())
			if err := server.Serve(l); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("could not start HTTP server: %w", err)
			}
			c.Logf("oauth2cli: stopped HTTP server at %s", l.Addr())
		}
		return nil
	})
	if c.LocalServerReadyChan != nil {
		c.LocalServerReadyChan <- c.OAuth2Config.RedirectURL
	}

	if err := eg.Wait(); err != nil {
		return "", fmt.Errorf("authorization error: %w", err)
	}
	if resp == nil {
		return "", errors.New("no authorization response")
	}
	return resp.code, resp.err
}

func computeRedirectURL(l net.Listener, c *Config) string {
	hostPort := fmt.Sprintf("%s:%d", c.RedirectURLHostname, l.Addr().(*net.TCPAddr).Port)
	if c.LocalServerCertFile != "" {
		return "https://" + hostPort
	}
	return "http://" + hostPort
}

type authorizationResponse struct {
	code string // non-empty if a valid code is received
	err  error  // non-nil if an error is received or any error occurs
}

type localServerHandler struct {
	config     *Config
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
	authCodeURL := h.config.OAuth2Config.AuthCodeURL(h.config.State, h.config.AuthCodeOptions...)
	h.config.Logf("oauth2cli: sending redirect to %s", authCodeURL)
	http.Redirect(w, r, authCodeURL, 302)
}

func (h *localServerHandler) handleCodeResponse(w http.ResponseWriter, r *http.Request) *authorizationResponse {
	q := r.URL.Query()
	code, state := q.Get("code"), q.Get("state")

	if state != h.config.State {
		http.Error(w, "authorization error", 500)
		return &authorizationResponse{err: fmt.Errorf("state does not match (wants %s but got %s)", h.config.State, state)}
	}
	w.Header().Add("Content-Type", "text/html")
	if _, err := fmt.Fprintf(w, h.config.LocalServerSuccessHTML); err != nil {
		http.Error(w, "server error", 500)
		return &authorizationResponse{err: fmt.Errorf("write error: %w", err)}
	}
	return &authorizationResponse{code: code}
}

func (h *localServerHandler) handleErrorResponse(w http.ResponseWriter, r *http.Request) *authorizationResponse {
	q := r.URL.Query()
	errorCode, errorDescription := q.Get("error"), q.Get("error_description")

	http.Error(w, "authorization error", 500)
	return &authorizationResponse{err: fmt.Errorf("authorization error from server: %s %s", errorCode, errorDescription)}
}
