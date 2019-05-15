package main

import (
	"context"
	"log"
	"os"

	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	clientID, clientSecret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatalf("You need to set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
	}

	ctx := context.Background()
	flow := oauth2cli.AuthCodeFlow{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"email"},
		},
		ShowLocalServerURL: func(url string) {
			log.Printf("Open %s", url)
		},
	}
	token, err := flow.GetToken(ctx)
	if err != nil {
		log.Fatalf("Could not get a token: %s", err)
	}
	log.Printf("Got a token: %+v", token)
	log.Printf("Your token is valid until %s", token.Expiry)
}
