package oauth2cli

import (
	"context"

	implicit_types "github.com/int128/oauth2cli/implicit"
	shared "github.com/int128/oauth2cli/internal"
	implicit_int "github.com/int128/oauth2cli/internal/implicit"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

// GetTokenImplicitly performs Implicit Grant Flow and returns a token from the provider.
// See https://tools.ietf.org/html/rfc6749#section-4.2
//
// This does the following steps:
//
//	1. Start a local server at the port.
//	2. Open a browser and navigate it to the local server.
//	3. Wait for the user authorization.
// 	4. Receive a token via an authorization response (HTTP redirect).
// 	5. Post the URL fragment via JavaScript to a local endpoint.
// 	6. Return the token.
//
func GetTokenImplicitly(ctx context.Context, c *implicit_types.ServerConfig) (token *oauth2.Token, err error) {
	if c.LocalServerMiddleware == nil {
		c.LocalServerMiddleware = shared.DefaultMiddleware
	}

	if c.LocalServerSuccessHTML == "" {
		c.LocalServerSuccessHTML = DefaultLocalServerSuccessHTML
	}

	token, _, err = implicit_int.ReceiveTokenViaLocalServer(ctx, c, []string{"token"})
	if err != nil {
		return token, xerrors.Errorf("error while receiving token: %w", err)
	}

	return token, err
}

// GetIDTokenImplicitly performs Implicit Grant Flow and returns a id_token from the provider.
// See https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
//
// This does the following steps:
//
//	1. Start a local server at the port.
//	2. Open a browser and navigate it to the local server.
//	3. Wait for the user authorization.
// 	4. Receive a id_token via an authorization response (HTTP redirect).
// 	5. Post the URL fragment via JavaScript to a local endpoint.
// 	6. Return the id_token.
//
// Note: it's up to the consumer to validate the id_token with the nonce value.
//
func GetIDTokenImplicitly(ctx context.Context, c *implicit_types.ServerConfig) (token *oauth2.Token, nonce string, err error) {
	if c.LocalServerMiddleware == nil {
		c.LocalServerMiddleware = shared.DefaultMiddleware
	}

	if c.LocalServerSuccessHTML == "" {
		c.LocalServerSuccessHTML = DefaultLocalServerSuccessHTML
	}

	token, nonce, err = implicit_int.ReceiveTokenViaLocalServer(ctx, c, []string{"id_token"})
	if err != nil {
		return token, nonce, xerrors.Errorf("error while receiving token: %w", err)
	}

	return token, nonce, err
}

// GeTokenIDTokenImplicitly performs Implicit Grant Flow and returns a token and id_token from the provider.
// See https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
//
// This does the following steps:
//
//	1. Start a local server at the port.
//	2. Open a browser and navigate it to the local server.
//	3. Wait for the user authorization.
// 	4. Receive a id_token via an authorization response (HTTP redirect).
// 	5. Post the URL fragment via JavaScript to a local endpoint.
// 	6. Return the id_token.
//
// Note: it's up to the consumer to validate the id_token with the nonce value.
//
func GeTokenIDTokenImplicitly(ctx context.Context, c *implicit_types.ServerConfig) (token *oauth2.Token, nonce string, err error) {
	if c.LocalServerMiddleware == nil {
		c.LocalServerMiddleware = shared.DefaultMiddleware
	}

	if c.LocalServerSuccessHTML == "" {
		c.LocalServerSuccessHTML = DefaultLocalServerSuccessHTML
	}

	token, nonce, err = implicit_int.ReceiveTokenViaLocalServer(ctx, c, []string{"token", "id_token"})
	if err != nil {
		return token, nonce, xerrors.Errorf("error while receiving token: %w", err)
	}

	return token, nonce, err
}
