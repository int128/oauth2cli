package oauth2cli

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/xerrors"
)

type localListener struct {
	net.Listener
	URL string
}

// newLocalListener starts a TCP listener on the given host.
// If multiple ports are given, it will try the ports in order.
// If nil or an empty slice is given, it will allocate a free port.
func newLocalListener(host string, ports []int) (*localListener, error) {
	if len(ports) == 0 {
		return newLocalListenerAt(host, 0)
	}
	var errs []string
	for _, port := range ports {
		l, err := newLocalListenerAt(host, port)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return l, nil
	}
	return nil, xerrors.Errorf("no available port (%s)", strings.Join(errs, ", "))
}

func newLocalListenerAt(host string, port int) (*localListener, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, xerrors.Errorf("could not listen: %w", err)
	}
	addr := l.Addr().String()
	_, p, err := net.SplitHostPort(addr)
	url := fmt.Sprintf("http://localhost:%s", p)
	return &localListener{l, url}, nil
}
