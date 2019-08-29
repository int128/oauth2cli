# oauth2cli [![CircleCI](https://circleci.com/gh/int128/oauth2cli.svg?style=shield)](https://circleci.com/gh/int128/oauth2cli) [![GoDoc](https://godoc.org/github.com/int128/oauth2cli?status.svg)](https://godoc.org/github.com/int128/oauth2cli)

This is a Go package for authorization in a command line interface (CLI) application.
It allows intuitive user interaction using [OAuth 2.0 Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1) and the local server.

See the [example](example/) for more.


## Why

When we implement the OAuth 2.0 Authorization Code Grant in a CLI application, it should be complicated user interaction.
For example,

1. User runs the command on a terminal.
1. User opens the URL shown on the command.
1. User logs in to the provider.
1. User copies the code shown on the browser.
1. User pastes the code on the terminal.
1. User can access to the API using the token.

By using oauth2cli, user interaction is very simple and easy.
For example,

1. User runs the command on a terminal.
1. The command opens the browser.
1. User logs in to the provider.
1. The command gets a token from the provider.
1. User can access to the API using the token.


## How it works

oauth2cli performs the following steps:

1. Start a local server at the port.
2. Send the URL of the local server to the channel.
   You can open a browser and navigate it to the URL.
3. Wait for the user authorization.
4. Receive a code via an authorization response (HTTP redirect).
5. Exchange the code and a token.
6. Return the code.


## Contributions

This is an open source software licensed under Apache 2.0.
Feel free to open issues and pull requests.
