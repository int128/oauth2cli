package implicit

import (
	"net/http"
)

// Config describes a typical OAuth2 Implicit flow, with both the
// client application information and the server's endpoint URLs.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// AuthURL represents an OAuth 2.0 provider's authorization endpoint URL.
	AuthURL string

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string
}

// ServerConfig represents a config for GetToken.
type ServerConfig struct {
	Config Config

	// Address which the local server binds to.
	// Set to "0.0.0.0" to bind all interfaces.
	// Default to "127.0.0.1".
	LocalServerAddress string
	// Candidates of a port which the local server binds to.
	// If multiple ports are given, it will try the ports in order.
	// If nil or an empty slice is given, it will allocate a free port.
	LocalServerPort []int
	// A PEM-encoded certificate, and possibly the complete certificate chain.
	// When set, the server will serve TLS traffic using the specified
	// certificates. It's recommended that the public key's SANs contain
	// the loopback addresses - 'localhost', '127.0.0.1' and '::1'
	LocalServerCertFile string
	// A PEM-encoded private key for the certificate.
	// This is required when LocalServerCertFile is set.
	LocalServerKeyFile string
	// Response HTML body on authorization completed.
	// Default to DefaultLocalServerSuccessHTML.
	LocalServerSuccessHTML string
	// Middleware for the local server. Default to none.
	LocalServerMiddleware func(h http.Handler) http.Handler
	// A channel to send its URL when the local server is ready. Default to none.
	LocalServerReadyChan chan<- string
}
