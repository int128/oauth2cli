package main

import (
	"context"
	"flag"
	"github.com/int128/oauth2cli"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
	"log"
	"os"
)

type cmdOptions struct {
	clientID        string
	clientSecret    string
	localServerCert string
	localServerKey  string
}

func main() {
	var o cmdOptions
	flag.StringVar(&o.clientID, "client-id", "", "OAuth Client ID")
	flag.StringVar(&o.clientSecret, "client-secret", "", "OAuth Client Secret")
	flag.StringVar(&o.localServerCert, "local-server-cert", "", "Path to a certificate file for the local server (optional)")
	flag.StringVar(&o.localServerKey, "local-server-key", "", "Path to a key file for the local server (optional)")
	flag.Parse()
	if o.clientID == "" || o.clientSecret == "" {
		log.Printf(`You need to set oauth2 credentials.
Open https://console.cloud.google.com/apis/credentials and create a client.
Then set the following options:`)
		flag.PrintDefaults()
		os.Exit(1)
		return
	}
	if o.localServerCert != "" {
		log.Printf("Using a TLS certificate: %s", o.localServerCert)
	}

	ctx := context.Background()
	eg, ctx := errgroup.WithContext(ctx)
	ready := make(chan string, 1)
	defer close(ready)
	eg.Go(func() error {
		select {
		case url := <-ready:
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
		token, err := oauth2cli.GetToken(ctx, oauth2cli.Config{
			OAuth2Config: oauth2.Config{
				ClientID:     o.clientID,
				ClientSecret: o.clientSecret,
				Endpoint:     google.Endpoint,
				Scopes:       []string{"email"},
			},
			LocalServerReadyChan: ready,
			LocalServerCertFile:  o.localServerCert,
			LocalServerKeyFile:   o.localServerKey,
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
