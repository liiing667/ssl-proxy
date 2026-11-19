package reverseproxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
)

// CertPins maps an upstream host name to the expected SHA-256 fingerprint of
// that host's TLS certificate. Pins are scoped to a single host: a pin
// configured for one host never applies to a connection to any other host.
type CertPins map[string][32]byte

// NewSecureTransport returns an *http.Transport for egress to TLS upstreams
// that fails closed:
//   - the SNI and hostname verification for every connection are bound to the
//     actual connection target (never reused across hosts),
//   - TLS 1.2 is the minimum accepted version,
//   - when certificate pins are configured, the peer's leaf certificate
//     fingerprint must match the pin for the connected host, and any host
//     without its own pin is rejected.
func NewSecureTransport(pins CertPins) *http.Transport {
	return newSecureTransport(pins, nil)
}

func newSecureTransport(pins CertPins, rootCAs *x509.CertPool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		// ServerName is intentionally left unset so the transport derives the
		// SNI and the hostname to verify from each connection's actual target.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPin(cs, pins)
		},
	}
	return transport
}

// verifyPin fails closed unless the peer leaf certificate matches the pin
// configured for the host this connection was actually established to.
func verifyPin(cs tls.ConnectionState, pins CertPins) error {
	if len(pins) == 0 {
		return nil
	}
	host := strings.ToLower(cs.ServerName)
	pin, ok := lookupPin(pins, host)
	if !ok {
		return fmt.Errorf("ssl-proxy: no certificate pin configured for upstream host %q, refusing connection", host)
	}
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("ssl-proxy: upstream host %q presented no certificates", host)
	}
	if got := sha256.Sum256(cs.PeerCertificates[0].Raw); got != pin {
		return fmt.Errorf("ssl-proxy: certificate pin mismatch for upstream host %q", host)
	}
	return nil
}

func lookupPin(pins CertPins, host string) ([32]byte, bool) {
	for name, pin := range pins {
		if strings.ToLower(name) == host {
			return pin, true
		}
	}
	return [32]byte{}, false
}
