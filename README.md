# oauth2cli [![CircleCI](https://circleci.com/gh/int128/oauth2cli.svg?style=shield)](https://circleci.com/gh/int128/oauth2cli)

A Go library for better user experience on OAuth 2.0 and OpenID Connect (OIDC) on CLI.
It allows simple and easy user interaction with Authorization Code Grant Flow and a local server.

See [GoDoc](https://godoc.org/github.com/int128/oauth2cli).


## TL;DR

```go
import (
	"context"
	"log"

	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
)

var endpoint = oauth2.Endpoint{
	AuthURL:  "https://example.com/oauth2/auth",
	TokenURL: "https://example.com/oauth2/token",
}

func main() {
	ctx := context.Background()
	flow := oauth2cli.AuthCodeFlow{
		Config: oauth2.Config{
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			Endpoint:     endpoint,
			Scopes:       []string{"email"},
		},
	}
	token, err := flow.GetToken(ctx)
	if err != nil {
		log.Fatalf("Could not get a token: %s", err)
	}
    log.Printf("Got a token: %+v", token)
}
```


## Why

Typical OAuth 2.0 Authorization Code Grant implementation requires complicated user interaction.
For example,

1. User runs the command on a terminal.
1. User opens the URL shown on the command.
1. User logs in to the provider.
1. User copies the code shown on the browser.
1. User pastes the code on the terminal.
1. User can access to the API using the token.

By using `oauth2cli`, user interaction will be simple and easy as follows:

1. User runs the command on a terminal.
1. `oauth2cli` opens the browser automatically.
1. User logs in to the provider.
1. `oauth2cli` gets a token from the provider.
1. User can access to the API using the token.


## How it works

`oauth2cli` performs the following steps:

1. Start a local server at the port.
2. Open browser and navigate to the local server.
3. Wait for user authorization.
4. Receive a code via an authorization response (HTTP redirect).
5. Exchange the code and a token.
6. Return the code.


## Contributions

This is an open source software licensed under Apache 2.0.
Feel free to open issues and pull requests.
