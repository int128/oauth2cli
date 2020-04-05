// Package authserver provides a stub server of the OAuth 2.0 authorization server.
// This supports the authorization code grant described as:
// https://tools.ietf.org/html/rfc6749#section-4.1
package authserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// AuthorizationRequest represents an authorization request described as:
// https://tools.ietf.org/html/rfc6749#section-4.1.1
type AuthorizationRequest struct {
	Scope       string
	State       string
	RedirectURI string
	Raw         url.Values
}

// TokenRequest represents a token request described as:
// https://tools.ietf.org/html/rfc6749#section-4.1.3
type TokenRequest struct {
	Code string
	Raw  url.Values
}

// Handler handles HTTP requests.
type Handler struct {
	T *testing.T

	// This should return a URL with query parameters of authorization response.
	// See https://tools.ietf.org/html/rfc6749#section-4.1.2
	NewAuthorizationResponse func(r AuthorizationRequest) string

	// This should return a JSON body of access token response or error response.
	// See https://tools.ietf.org/html/rfc6749#section-5.1
	// and https://tools.ietf.org/html/rfc6749#section-5.2
	NewTokenResponse func(r TokenRequest) (int, string)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.T.Logf("authServer: %s %s", r.Method, r.RequestURI)
	if err := h.serveHTTP(w, r); err != nil {
		h.T.Errorf("Handler error: %s", err)
		http.Error(w, err.Error(), 500)
	}
}

func (h *Handler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	switch {
	case r.Method == "GET" && r.URL.Path == "/auth":
		q := r.URL.Query()
		scope, state, redirectURI := q.Get("scope"), q.Get("state"), q.Get("redirect_uri")
		if scope == "" {
			return errors.New("scope is missing")
		}
		if state == "" {
			return errors.New("state is missing")
		}
		if redirectURI == "" {
			return errors.New("redirect_uri is missing")
		}
		to := h.NewAuthorizationResponse(AuthorizationRequest{
			Scope:       scope,
			State:       state,
			RedirectURI: redirectURI,
			Raw:         q,
		})
		http.Redirect(w, r, to, 302)

	case r.Method == "POST" && r.URL.Path == "/token":
		if err := r.ParseForm(); err != nil {
			return fmt.Errorf("error while parsing form: %w", err)
		}
		code, redirectURI := r.Form.Get("code"), r.Form.Get("redirect_uri")
		if code == "" {
			return errors.New("code is missing")
		}
		if redirectURI == "" {
			return errors.New("redirect_uri is missing")
		}
		status, b := h.NewTokenResponse(TokenRequest{
			Code: code,
			Raw:  r.Form,
		})
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(b)); err != nil {
			return fmt.Errorf("error while writing response body: %w", err)
		}

	default:
		http.NotFound(w, r)
	}
	return nil
}
