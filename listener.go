package oauth2cli

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type localhostListener struct {
	net.Listener
	Port int
	URL  string
}

// newLocalhostListener starts a TCP listener on localhost.
// A random port is allocated if the port is 0.
func newLocalhostListener(port int) (*localhostListener, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, fmt.Errorf("Could not listen to port %d", port)
	}
	p, err := extractPort(l.Addr())
	if err != nil {
		return nil, fmt.Errorf("Could not determine listening port: %s", err)
	}
	url := fmt.Sprintf("http://localhost:%d", p)
	return &localhostListener{l, p, url}, nil
}

func extractPort(addr net.Addr) (int, error) {
	s := strings.SplitN(addr.String(), ":", 2)
	if len(s) != 2 {
		return 0, fmt.Errorf("Invalid address: %s", addr)
	}
	p, err := strconv.Atoi(s[1])
	if err != nil {
		return 0, fmt.Errorf("Invalid port number %s: %s", addr, err)
	}
	return p, nil
}
