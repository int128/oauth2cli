package main

import "testing"

func Test_computeChallengeAndVerifier(t *testing.T) {
	// https://tools.ietf.org/html/rfc7636#appendix-B
	b := []byte{
		116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
		187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
		132, 141, 121,
	}
	challenge, verifier := computeChallengeAndVerifier(b)
	if want := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; want != verifier {
		t.Errorf("verifier wants %s but was %s", want, verifier)
	}
	if want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; want != challenge {
		t.Errorf("challenge wants %s but was %s", want, challenge)
	}
}
