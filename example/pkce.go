package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"golang.org/x/xerrors"
)

func generateChallengeAndVerifier() (string, string, error) {
	b, err := random32()
	if err != nil {
		return "", "", xerrors.Errorf("could not generate PKCE parameters: %w", err)
	}
	codeChallenge, codeVerifier := computeChallengeAndVerifier(b)
	return codeChallenge, codeVerifier, nil
}

func computeChallengeAndVerifier(b []byte) (string, string) {
	verifier := base64URLEncode(b)
	s := sha256.New()
	_, _ = s.Write([]byte(verifier))
	challenge := base64URLEncode(s.Sum(nil))
	return challenge, verifier
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, xerrors.Errorf("read error: %w", err)
	}
	return b, nil
}

func base64URLEncode(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
