package reverseproxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"time"
)

// Headers carrying the authenticated client identity from the proxy to the
// downstream service. They are derived only from a verified client certificate.
const (
	HeaderForwardedClientCert = "X-Forwarded-Client-Cert"
	HeaderForwardedClientCN   = "X-Forwarded-Client-Cn"
	HeaderForwardedSubjectDN  = "X-Forwarded-Subject-Dn"
)

// spoofableIdentityHeaders are inbound request headers that downstream
// services may treat as an authenticated identity. They must never be taken
// at face value from the client.
var spoofableIdentityHeaders = []string{
	HeaderForwardedClientCert,
	HeaderForwardedClientCN,
	HeaderForwardedSubjectDN,
	"X-Forwarded-Tls-Client-Cert",
	"X-SSL-Client-Cert",
	"X-SSL-Client-S-Dn",
	"X-Client-Cert",
}

// ClientIdentity is the authenticated client derived from a verified TLS
// client certificate chain.
type ClientIdentity struct {
	Certificate *x509.Certificate
	RawDER      []byte
	SubjectDN   string
	CommonName  string
}

// ClientAuthenticator verifies TLS client certificates against a trusted
// certificate authority pool.
type ClientAuthenticator struct {
	roots *x509.CertPool
}

// RootPool returns the trusted CA pool so callers can configure their TLS
// listener with the same trust anchors as Authenticate.
func (a *ClientAuthenticator) RootPool() *x509.CertPool {
	return a.roots
}

// NewClientAuthenticator builds a ClientAuthenticator that trusts only the
// certificates in caPEM.
func NewClientAuthenticator(caPEM []byte) (*ClientAuthenticator, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errInvalidClientCAPEM
	}
	return &ClientAuthenticator{roots: pool}, nil
}

// Authenticate returns the authenticated client identity for the given TLS
// connection state, or an error when the peer cannot be authenticated.
func (a *ClientAuthenticator) Authenticate(state tls.ConnectionState) (*ClientIdentity, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, errNoClientCertificate
	}
	leaf := state.PeerCertificates[0]

	// Build the presented chain (leaf first) and verify it against the trusted
	// pool. A certificate is only treated as an authenticated subject when the
	// full chain, validity period, and clientAuth key usage verify together.
	intermediates := x509.NewCertPool()
	for _, intermediate := range state.PeerCertificates[1:] {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         a.roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(verifyOptions); err != nil {
		return nil, errUnverifiedClientCertificate
	}

	identity := &ClientIdentity{
		Certificate: leaf,
		RawDER:      leaf.Raw,
		SubjectDN:   leaf.Subject.String(),
		CommonName:  leaf.Subject.CommonName,
	}
	return identity, nil
}

// TLSConfig returns a TLS server configuration requesting client certificates
// while delegating all verification to Authenticate, which applies the
// configured trust pool, validity, and key-usage constraints explicitly.
func (a *ClientAuthenticator) TLSConfig() *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  a.roots,
		MinVersion: tls.VersionTLS12,
	}
}

// AddIdentityHeaders records the authenticated client identity on the proxied
// request so the downstream service can make authorization decisions.
func AddIdentityHeaders(req *http.Request, identity *ClientIdentity) {
	if identity == nil {
		return
	}
	req.Header.Set(http.CanonicalHeaderKey(HeaderForwardedClientCert), base64.StdEncoding.EncodeToString(identity.RawDER))
	req.Header.Set(http.CanonicalHeaderKey(HeaderForwardedClientCN), identity.CommonName)
	req.Header.Set(http.CanonicalHeaderKey(HeaderForwardedSubjectDN), identity.SubjectDN)
}

// stripInboundIdentityHeaders removes any identity headers supplied by the
// client so only proxy-derived identity reaches the downstream service.
func stripInboundIdentityHeaders(req *http.Request) {
	for _, header := range spoofableIdentityHeaders {
		req.Header.Del(http.CanonicalHeaderKey(header))
	}
}
