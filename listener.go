package oauth2cli

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/xerrors"
)

type localhostListener struct {
	net.Listener
	URL *url.URL // URL to the listener
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
	return &localhostListener{
		Listener: l,
		URL:      &url.URL{Host: fmt.Sprintf("localhost:%d", addr.Port), Scheme: "http"},
	}, nil
}
