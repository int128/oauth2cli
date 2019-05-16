// Package oauth2cli provides better user experience on OAuth 2.0 and OpenID Connect (OIDC) on CLI.
// It allows simple and easy user interaction with Authorization Code Grant Flow and a local server.
package oauth2cli

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

var defaultMiddleware = func(h http.Handler) http.Handler {
	return h
}

// DefaultLocalServerSuccessHTML is a default response body on authorization success.
const DefaultLocalServerSuccessHTML = `<html><body>OK<script>window.close()</script></body></html>`

// Config represents a config for GetToken.
type Config struct {
	OAuth2Config    oauth2.Config
	AuthCodeOptions []oauth2.AuthCodeOption

	// If true, skip opening the browser.
	SkipOpenBrowser bool
	// Candidates of a port which the local server binds to.
	// If multiple ports are given, it will try the ports in order.
	// If nil or an empty slice is given, it will allocate a free port.
	LocalServerPort []int
	// Response HTML body on authorization completed.
	// Default to DefaultLocalServerSuccessHTML.
	LocalServerSuccessHTML string
	// Called when the local server is started. Default to none.
	ShowLocalServerURL func(url string)
	// Middleware for the local server. Default to none.
	LocalServerMiddleware func(h http.Handler) http.Handler
}

// GetToken performs Authorization Code Grant Flow and returns a token got from the provider.
// See https://tools.ietf.org/html/rfc6749#section-4.1
//
// This does the following steps:
//
//	1. Start a local server at the port.
//	2. Open a browser and navigate it to the local server.
//	3. Wait for the user authorization.
// 	4. Receive a code via an authorization response (HTTP redirect).
// 	5. Exchange the code and a token.
// 	6. Return the code.
//
func GetToken(ctx context.Context, config Config) (*oauth2.Token, error) {
	if config.LocalServerMiddleware == nil {
		config.LocalServerMiddleware = defaultMiddleware
	}
	if config.LocalServerSuccessHTML == "" {
		config.LocalServerSuccessHTML = DefaultLocalServerSuccessHTML
	}
	code, err := receiveCodeViaLocalServer(ctx, &config)
	if err != nil {
		return nil, errors.Wrapf(err, "error while receiving an authorization code")
	}
	token, err := config.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, errors.Wrapf(err, "error while exchanging authorization code and token")
	}
	return token, nil
}
