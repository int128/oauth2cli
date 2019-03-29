// Package oauth2cli provides better user experience on OAuth 2.0 and OpenID Connect (OIDC) on CLI.
// It allows simple and easy user interaction with Authorization Code Grant Flow and a local server.
package oauth2cli

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
)

func newOAuth2State() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", errors.Wrapf(err, "error while reading random")
	}
	return fmt.Sprintf("%x", n), nil
}
