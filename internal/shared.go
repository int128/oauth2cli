package internal

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"

	"golang.org/x/xerrors"
)

// ExpandAddresses returns a slice of addresses for every port
func ExpandAddresses(address string, ports []int) (addresses []string) {
	for _, port := range ports {
		addresses = append(addresses, fmt.Sprintf("%s:%d", address, port))
	}
	return
}

// NewOAuth2State retruns random state
func NewOAuth2State() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", xerrors.Errorf("error while reading random: %w", err)
	}
	return fmt.Sprintf("%x", n), nil
}

// DefaultMiddleware returns h handler
func DefaultMiddleware(h http.Handler) http.Handler {
	return h
}
