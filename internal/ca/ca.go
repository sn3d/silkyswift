// Package ca implements a load-or-generate certificate authority and a
// per-SNI leaf certificate cache for use with tls.Config.GetCertificate.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

// Authority owns the root CA and a cache of per-domain leaf certs.
type Authority struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey

	mu        sync.Mutex
	leafCache map[string]*tls.Certificate
}

// LoadOrGenerate reads an existing CA cert+key from disk if both parse
// successfully and the public key in the cert matches the private key,
// otherwise generates a fresh P-256 CA and writes new PEM files
// (0644 cert, 0600 key). The user only needs to install the resulting
// ca.crt into their trust store once.
func LoadOrGenerate(certPath, keyPath string) (*Authority, error) {
	cert, key, loadErr := loadCA(certPath, keyPath)
	if loadErr == nil {
		return &Authority{
			caCert:    cert,
			caKey:     key,
			leafCache: make(map[string]*tls.Certificate),
		}, nil
	}
	// Don't warn on first-run "file doesn't exist" — that's expected.
	if !os.IsNotExist(loadErr) {
		log.Printf("CA not reusable (%v), generating a fresh CA", loadErr)
	}

	cert, key, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", cert.Raw, 0644); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}

	return &Authority{
		caCert:    cert,
		caKey:     key,
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

// LeafFor implements tls.Config.GetCertificate. It returns a leaf cert
// whose DNS SAN matches hello.ServerName, minting and caching on first
// miss.
func (a *Authority) LeafFor(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		return nil, fmt.Errorf("client did not send SNI")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if cert, ok := a.leafCache[domain]; ok {
		return cert, nil
	}

	cert, err := a.signLeaf(domain)
	if err != nil {
		return nil, err
	}
	a.leafCache[domain] = cert
	return cert, nil
}

func (a *Authority) signLeaf(domain string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.caCert, &leafKey.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}

	// Parse once so the TLS stack doesn't re-parse on every handshake.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der, a.caCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, nil
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "SilkySwift CA",
			Organization: []string{"SilkySwift"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated CA: %w", err)
	}
	return cert, key, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA")
	}

	// Make sure the loaded pair is actually a usable CA and that the cert's
	// public key matches the private key — otherwise signing silently
	// produces leaves no client will trust.
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("loaded cert is not a CA")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA cert public key is not ECDSA")
	}
	if !pub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("CA cert and key do not match")
	}
	return cert, key, nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
