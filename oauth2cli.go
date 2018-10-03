// Package oauth2cli provides ...
package oauth2cli

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

type oauth2State string

func newOAuth2State() (oauth2State, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	return oauth2State(fmt.Sprintf("%x", n)), nil
}
