package reverseproxy

import "errors"

var (
	errInvalidClientCAPEM          = errors.New("reverseproxy: no valid client CA certificates found in PEM")
	errNoClientCertificate         = errors.New("reverseproxy: client did not present a certificate")
	errUnverifiedClientCertificate = errors.New("reverseproxy: client certificate chain is not verified")
)
