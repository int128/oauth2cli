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

	// open the browser on ready (this is optional)
	ready := make(chan string)
	defer close(ready)
	go func() {
		select {
		case url, ok := <-ready:
			if ok {
				log.Printf("Open %s", url)
			} else {
				log.Printf("channel has been closed while waiting for authorization")
			}
		case err := <-ctx.Done():
			log.Printf("context done while waiting for authorization: %s", err)
		}
	}()

	// perform authorization
	token, err := oauth2cli.GetToken(ctx, oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"email"},
		},
		LocalServerReadyChan: ready,
	})
	if err != nil {
		log.Fatalf("Could not get a token: %s", err)
	}
	log.Printf("Got a token: %+v", token)
	log.Printf("Your token is valid until %s", token.Expiry)
}
