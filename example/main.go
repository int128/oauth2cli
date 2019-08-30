package main

import (
	"context"
	"log"
	"os"

	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

func main() {
	ctx := context.Background()
	clientID, clientSecret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatalf("You need to set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
	}

	ready := make(chan string, 1)
	var eg errgroup.Group
	eg.Go(func() error {
		select {
		case url, ok := <-ready:
			if !ok {
				return nil
			}
			log.Printf("Open %s", url)
			// you can open the browser here
			return nil
		case err := <-ctx.Done():
			return xerrors.Errorf("context done while waiting for authorization: %w", err)
		}
	})
	eg.Go(func() error {
		defer close(ready)
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
			return xerrors.Errorf("could not get a token: %w", err)
		}
		log.Printf("Got a token: %+v", token)
		log.Printf("Your token is valid until %s", token.Expiry)
		return nil
	})
	if err := eg.Wait(); err != nil {
		log.Printf("error while authorization: %s", err)
	}
}
