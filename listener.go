package oauth2cli

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
)

type localhostListener struct {
	net.Listener
	URL string
}

// newLocalhostListener starts a TCP listener on localhost.
// A random port is allocated if the port is 0.
func newLocalhostListener(port int) (*localhostListener, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, errors.Wrapf(err, "error while listening on port %d", port)
	}
	_, p, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return nil, errors.Wrapf(err, "error while listening port allocation")
	}
	url := fmt.Sprintf("http://localhost:%s", p)
	return &localhostListener{l, url}, nil
}
