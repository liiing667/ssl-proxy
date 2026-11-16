package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// minTLSVersion is the minimum TLS version the proxy will negotiate.
const minTLSVersion = tls.VersionTLS12

// buildTLSConfig centralizes certificate validation and TLS version policy.
// When domain is set, certificates are minted on demand via LetsEncrypt (autocert);
// otherwise the certificate and private key are loaded and validated from
// certFile/keyFile. Errors never include certificate or private key contents.
func buildTLSConfig(domain, certFile, keyFile string) (*tls.Config, error) {
	if domain != "" {
		m := &autocert.Manager{
			Cache:      autocert.DirCache("certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
		}
		cfg := m.TLSConfig()
		cfg.MinVersion = minTLSVersion
		return cfg, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		// Only surface the file paths and the (content-free) standard library
		// reason; never the certificate or private key material itself.
		return nil, fmt.Errorf("unable to load TLS certificate/key pair (cert: %q, key: %q): %w", certFile, keyFile, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minTLSVersion,
	}, nil
}

// startupTLS performs the fail-closed startup transaction: the TLS
// configuration (including certificate/key validation) is fully built and
// verified before any network port is bound. On success it returns a server
// and a TLS-wrapped listener ready to Serve; on failure no port is bound.
func startupTLS(domain, certFile, keyFile, addr string, handler http.Handler) (*http.Server, net.Listener, error) {
	tlsConfig, err := buildTLSConfig(domain, certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to listen on %q: %w", addr, err)
	}
	server := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
	return server, tls.NewListener(listener, tlsConfig), nil
}

// startHTTPRedirect starts a server on port 80 that permanently redirects all
// HTTP requests to HTTPS using redirectURL as the host. Failures are logged
// but do not affect the main TLS server.
func startHTTPRedirect(redirectURL string) {
	redirectTLS := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+redirectURL+r.RequestURI, http.StatusMovedPermanently)
	}
	go func() {
		log.Printf("Also redirecting http requests on port 80 to https requests on %s", redirectURL)
		if err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS)); err != nil {
			log.Println("HTTP redirection server failure")
			log.Println(err)
		}
	}()
}
