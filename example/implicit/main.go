package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/implicit"
	"github.com/pkg/browser"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

type cmdOptions struct {
	clientID        string
	localServerCert string
	localServerKey  string
}

func main() {
	var o cmdOptions
	flag.StringVar(&o.clientID, "client-id", "", "OAuth Client ID")
	flag.StringVar(&o.localServerCert, "local-server-cert", "", "Path to a certificate file for the local server")
	flag.StringVar(&o.localServerKey, "local-server-key", "", "Path to a key file for the local server")
	flag.Parse()

	if o.clientID == "" {
		log.Printf(`You need to set oauth2 credentials.
Open https://console.cloud.google.com/apis/credentials and create a client.
Then set the following options:`)
		flag.PrintDefaults()
		os.Exit(1)
		return
	}

	if o.localServerCert == "" || o.localServerKey == "" {
		log.Printf("Certificate and key are required")
		flag.PrintDefaults()
		os.Exit(1)
		return
	}

	ctx := context.Background()

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
		token, nonce, err := oauth2cli.GeTokenIDTokenImplicitly(ctx, &implicit.ServerConfig{
			LocalServerPort:      []int{8000},
			LocalServerReadyChan: ready,
			LocalServerCertFile:  o.localServerCert,
			LocalServerKeyFile:   o.localServerKey,
			Config: implicit.Config{
				ClientID:    o.clientID,
				AuthURL:     google.Endpoint.AuthURL,
				RedirectURL: "https://localhost:8000/implicit",
				Scopes:      []string{"openid"},
			},
		})
		if err != nil {
			return xerrors.Errorf("could not get a token: %w", err)
		}
		log.Printf("You got a valid token: %+v\nnonce: %q", *token, nonce)
		return nil
	})
	if err := eg.Wait(); err != nil {
		log.Printf("error while authorization: %s", err)
	}
}
