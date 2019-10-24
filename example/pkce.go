package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"log"
	"strings"

	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
)

func configurePKCE(cfg *oauth2cli.Config) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		log.Fatalf("error: %s", err)
	}
	codeChallenge, codeVerifier := computeChallengeAndVerifier(b)
	cfg.AuthCodeOptions = []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
	}
	cfg.TokenRequestOptions = []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	}
}

func computeChallengeAndVerifier(b []byte) (string, string) {
	verifier := base64urlencode(b)
	s := sha256.New()
	_, _ = s.Write([]byte(verifier))
	challenge := base64urlencode(s.Sum(nil))
	return challenge, verifier
}

func base64urlencode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
