package main

import (
	"context"
	"log"
	"os"

	"github.com/int128/oauth2cli"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

func main() {
	ctx := context.Background()
	clientID, clientSecret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatalf(`You need to set oauth2 credentials.
Open https://console.cloud.google.com/apis/credentials and create a client. And then,
export GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=xxx
`)
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
			if err := browser.OpenURL(url); err != nil {
				log.Printf("could not open the browser: %s", err)
			}
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
		log.Printf("You got a valid token until %s", token.Expiry)
		return nil
	})
	if err := eg.Wait(); err != nil {
		log.Printf("error while authorization: %s", err)
	}
}
