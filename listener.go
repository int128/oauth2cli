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
// If multiple ports are given, it will try the ports in order.
// If nil or an empty slice is given, it will allocate a free port.
func newLocalhostListener(ports []int) (*localhostListener, error) {
	if len(ports) == 0 {
		return newLocalhostListenerAt(0)
	}
	for _, port := range ports {
		l, err := newLocalhostListenerAt(port)
		if err != nil {
			continue
		}
		return l, nil
	}
	return nil, errors.Errorf("could not bind any port of %v", ports)
}

func newLocalhostListenerAt(port int) (*localhostListener, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, errors.Wrapf(err, "error while listening on port %d", port)
	}
	addr := l.Addr().String()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.Wrapf(err, "error while parsing the address %s", addr)
	}
	url := fmt.Sprintf("http://localhost:%s", p)
	return &localhostListener{l, url}, nil
}
