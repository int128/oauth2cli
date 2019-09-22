package oauth2cli

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/xerrors"
)

type localhostListener struct {
	net.Listener
	URL string
}

// newLocalhostListener starts a TCP listener on localhost.
//
// If an address is given, it will bind the address. It defaults to localhost.
// Note that this always returns a localhost URL regardless of the address.
//
// If multiple ports are given, it will try the ports in order.
// If nil or an empty slice is given, it will allocate a free port.
func newLocalhostListener(address string, ports []int) (*localhostListener, error) {
	if len(ports) == 0 {
		return newLocalhostListenerAt(address, 0)
	}
	var errs []string
	for _, port := range ports {
		l, err := newLocalhostListenerAt(address, port)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return l, nil
	}
	return nil, xerrors.Errorf("no available port (%s)", strings.Join(errs, ", "))
}

// newLocalhostListenerAt starts a TCP listener on localhost and given port.
//
// If an address is given, it will bind the address. It defaults to localhost.
// Note that this always returns a localhost URL regardless of the address.
func newLocalhostListenerAt(address string, port int) (*localhostListener, error) {
	if address == "" {
		address = "localhost"
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		return nil, xerrors.Errorf("could not listen: %w", err)
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return nil, xerrors.Errorf("internal error: unknown type %T", l.Addr())
	}
	url := fmt.Sprintf("http://localhost:%d", addr.Port)
	return &localhostListener{l, url}, nil
}
