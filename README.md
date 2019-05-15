# oauth2cli [![CircleCI](https://circleci.com/gh/int128/oauth2cli.svg?style=shield)](https://circleci.com/gh/int128/oauth2cli) [![GoDoc](https://godoc.org/github.com/int128/oauth2cli?status.svg)](https://godoc.org/github.com/int128/oauth2cli)

This is a Go package for better user experience with OAuth 2.0 or OpenID Connect (OIDC) on command line interface.
It allows simple and easy user interaction with the Authorization Code Grant Flow using a local server.

See the [example](example/) using oauth2cli.


## Why

Typical implementation of the OAuth 2.0 Authorization Code Grant requires complicated user interaction, for example:

1. User runs the command on a terminal.
1. User opens the URL shown on the command.
1. User logs in to the provider.
1. User copies the code shown on the browser.
1. User pastes the code on the terminal.
1. User can access to the API using the token.

By using oauth2cli, user interaction becomes simple and easy as follows:

1. User runs the command on a terminal.
1. `oauth2cli` opens the browser automatically.
1. User logs in to the provider.
1. `oauth2cli` gets a token from the provider.
1. User can access to the API using the token.


## How it works

oauth2cli performs the following steps:

1. Start a local server at the port.
2. Open a browser and navigate it to the local server.
3. Wait for the user authorization.
4. Receive a code via an authorization response (HTTP redirect).
5. Exchange the code and a token.
6. Return the code.


## Contributions

This is an open source software licensed under Apache 2.0.
Feel free to open issues and pull requests.
