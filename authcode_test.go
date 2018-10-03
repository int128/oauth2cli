package oauth2cli_test

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

func ExampleAuthCodeFlow() {
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
	log.Printf("Got access token %s", token.AccessToken)
}
