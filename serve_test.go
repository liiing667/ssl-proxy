package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suyashkumar/ssl-proxy/gen"
)

// writeTestCertAndKey generates a self-signed cert/key pair and writes them to
// a temporary directory, returning the file paths and the private key contents.
func writeTestCertAndKey(t *testing.T) (certFile, keyFile, keyContents string) {
	t.Helper()
	certBuf, keyBuf, _, err := gen.Keys(time.Hour)
	if err != nil {
		t.Fatalf("unable to generate test keys: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certBuf.Bytes(), 0600); err != nil {
		t.Fatalf("unable to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyBuf.Bytes(), 0600); err != nil {
		t.Fatalf("unable to write key file: %v", err)
	}
	return certFile, keyFile, keyBuf.String()
}

// freeAddr returns a currently-unbound loopback address.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to reserve a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("unable to release port: %v", err)
	}
	return addr
}

func TestBuildTLSConfig_FileCert(t *testing.T) {
	certFile, keyFile, _ := writeTestCertAndKey(t)
	cfg, err := buildTLSConfig("", certFile, keyFile)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %x, want %x (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates: got %d, want 1", len(cfg.Certificates))
	}
}

func TestBuildTLSConfig_Domain(t *testing.T) {
	cfg, err := buildTLSConfig("example.com", "", "")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %x, want %x (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate: got nil, want autocert-backed callback")
	}
}

func TestBuildTLSConfig_ErrorDoesNotLeakKey(t *testing.T) {
	certFile, keyFile, keyContents := writeTestCertAndKey(t)
	// Corrupt the certificate so loading the pair fails
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("unable to corrupt cert file: %v", err)
	}
	_, err := buildTLSConfig("", certFile, keyFile)
	if err == nil {
		t.Fatal("got nil error, want certificate load failure")
	}
	// The error must reference the paths but never the private key material
	keyMarker := keyContents[30:80]
	if strings.Contains(err.Error(), keyMarker) {
		t.Errorf("error leaks private key contents: %v", err)
	}
	if !strings.Contains(err.Error(), certFile) || !strings.Contains(err.Error(), keyFile) {
		t.Errorf("error should reference cert/key paths, got: %v", err)
	}
}

func TestStartupTLS_FailsClosedOnBadCert(t *testing.T) {
	_, keyFile, _ := writeTestCertAndKey(t)
	addr := freeAddr(t)

	_, _, err := startupTLS("", "does-not-exist.pem", keyFile, addr, http.NewServeMux())
	if err == nil {
		t.Fatal("got nil error, want certificate load failure")
	}

	// Fail-closed: the listening port must not have been bound, so binding it
	// again must succeed
	l, listenErr := net.Listen("tcp", addr)
	if listenErr != nil {
		t.Fatalf("port %s was bound despite certificate validation failure", addr)
	}
	l.Close()
}

func TestStartupTLS_ServesHTTPS(t *testing.T) {
	certFile, keyFile, _ := writeTestCertAndKey(t)
	addr := freeAddr(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	server, listener, err := startupTLS("", certFile, keyFile, addr, mux)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	defer server.Close()
	go server.Serve(listener)

	// TLS 1.2 clients can connect
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body: got %q, want %q", body, "ok")
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version: got %x, want >= TLS 1.2", resp.TLS.Version)
	}

	// TLS 1.0 clients are rejected
	_, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS10})
	if err == nil {
		t.Error("TLS 1.0 handshake succeeded, want rejection (MinVersion TLS 1.2)")
	}
}
