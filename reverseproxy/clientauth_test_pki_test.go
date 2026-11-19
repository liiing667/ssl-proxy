package reverseproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type testPKI struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caPEM    []byte
	otherCA  *x509.Certificate
	otherKey *ecdsa.PrivateKey
}

func newTestPKI() *testPKI {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	caTemplate := testCertTemplate("Test Root CA", true)
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}

	otherTemplate := testCertTemplate("Other Root CA", true)
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	if err != nil {
		panic(err)
	}
	otherCert, err := x509.ParseCertificate(otherDER)
	if err != nil {
		panic(err)
	}

	return &testPKI{
		caCert:   caCert,
		caKey:    caKey,
		caPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		otherCA:  otherCert,
		otherKey: otherKey,
	}
}

// serverTLSConfig returns a server TLS configuration carrying a valid server
// certificate so the handshake can complete and reach client-cert exchange.
func (p *testPKI) serverTLSConfig(clientAuth tls.ClientAuthType, roots *x509.CertPool) *tls.Config {
	serverLeaf := p.issueLeaf("proxy.test", nil, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	config := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverLeaf.cert.Raw, p.caCert.Raw},
			PrivateKey:  serverLeaf.key,
			Leaf:        serverLeaf.cert,
		}},
		ClientAuth: clientAuth,
		MinVersion: tls.VersionTLS12,
	}
	if roots != nil {
		config.ClientCAs = roots
	}
	return config
}

func testCertTemplate(cn string, isCA bool) *x509.Certificate {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"ssl-proxy-test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if isCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	return template
}

// issueLeaf creates a client-auth leaf certificate signed by the given issuer.
func (p *testPKI) issueLeaf(cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) *tlsCert {
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := testCertTemplate(cn, false)
	template.NotBefore = notBefore
	template.NotAfter = notAfter
	if eku != nil {
		template.ExtKeyUsage = eku
	}
	parent := issuer
	if parent == nil {
		parent = p.caCert
	}
	key := issuerKey
	if key == nil {
		key = p.caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &leafKey.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &tlsCert{cert: cert, key: leafKey}
}

// selfSignedLeaf creates a self-signed client certificate trusted by no CA.
func (p *testPKI) selfSignedLeaf(cn string) *tlsCert {
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := testCertTemplate(cn, false)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &leafKey.PublicKey, leafKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &tlsCert{cert: cert, key: leafKey}
}

// issueIntermediateCA creates an intermediate CA signed by the trusted root.
func (p *testPKI) issueIntermediateCA(cn string) *tlsCert {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := testCertTemplate(cn, true)
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &tlsCert{cert: cert, key: key}
}

type tlsCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}
