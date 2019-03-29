package oauth2cli_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/int128/oauth2cli"
	"github.com/pkg/errors"
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
	log.Printf("Got a token: %+v", token)
}

func TestAuthCodeFlow_GetToken(t *testing.T) {
	// Start an auth server.
	h := authServerHandler{
		AuthCode:     "AUTH_CODE",
		Scope:        "email",
		AccessToken:  "ACCESS_TOKEN",
		RefreshToken: "REFRESH_TOKEN",
	}
	s := httptest.NewServer(&h)
	defer s.Close()
	endpoint := oauth2.Endpoint{
		AuthURL:  s.URL + "/auth",
		TokenURL: s.URL + "/token",
	}

	// Wait for the local server and open a browser request.
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()
	openBrowserCh := make(chan string)
	go func() {
		select {
		case url := <-openBrowserCh:
			if err := openBrowserRequest(url); err != nil {
				cancel()
				t.Errorf("Could not open browser request: %+v", err)
			}
		case <-ctx.Done():
			t.Errorf("Context done while waiting for opening browser: %+v", ctx.Err())
		}
	}()

	// Start a local server and get a token.
	flow := oauth2cli.AuthCodeFlow{
		Config: oauth2.Config{
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			Endpoint:     endpoint,
			Scopes:       []string{"email"},
		},
		SkipOpenBrowser: true,
		ShowLocalServerURL: func(url string) {
			openBrowserCh <- url
		},
	}
	token, err := flow.GetToken(ctx)
	if err != nil {
		t.Errorf("Could not get a token: %+v", err)
		return
	}
	if h.AccessToken != token.AccessToken {
		t.Errorf("AccessToken wants %s but %s", h.AccessToken, token.AccessToken)
	}
	if h.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken wants %s but %s", h.AccessToken, token.AccessToken)
	}
}

func openBrowserRequest(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return errors.Wrapf(err, "error while sending a request")
	}
	if resp.StatusCode != 200 {
		return errors.Errorf("StatusCode wants 200 but %d", resp.StatusCode)
	}
	return nil
}

type authServerHandler struct {
	Scope        string
	AuthCode     string
	AccessToken  string
	RefreshToken string
}

func (h *authServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.serveHTTP(w, r); err != nil {
		log.Printf("[authServer] Error: %s", err)
		w.WriteHeader(500)
	}
}

func (h *authServerHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	switch {
	case r.Method == "GET" && r.URL.Path == "/auth":
		q := r.URL.Query()
		if h.Scope != q.Get("scope") {
			return fmt.Errorf("scope wants %s but %s", h.Scope, q.Get("scope"))
		}
		to := fmt.Sprintf("%s?state=%s&code=%s", q.Get("redirect_uri"), q.Get("state"), h.AuthCode)
		http.Redirect(w, r, to, 302)

	case r.Method == "POST" && r.URL.Path == "/token":
		if err := r.ParseForm(); err != nil {
			return errors.Wrapf(err, "error while parsing form")
		}
		if h.AuthCode != r.Form.Get("code") {
			return errors.Errorf("code wants %s but %s", h.AuthCode, r.Form.Get("code"))
		}
		w.Header().Add("Content-Type", "application/json")
		b := fmt.Sprintf(`{
			"access_token": "%s",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token": "%s"
		}`, h.AccessToken, h.RefreshToken)
		if _, err := w.Write([]byte(b)); err != nil {
			return errors.Wrapf(err, "error while writing body")
		}

	default:
		http.Error(w, "Not Found", 404)
	}
	return nil
}
