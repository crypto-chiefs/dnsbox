package letsencrypt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
)

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err == nil && serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, err
}

func loadLocalCA() (*x509.Certificate, crypto.Signer, error) {
	path := filepath.Join(config.DataDir, "ca", "root.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid local CA: %w", err)
	}
	root, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, nil, fmt.Errorf("local CA is not a self-signed CA")
	}
	now := time.Now()
	if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return nil, nil, fmt.Errorf("local CA expired or not yet valid; rotate the CA and update client trust")
	}
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("invalid local CA signing key")
	}
	return root, key, nil
}

func ensureLocalCA() (*x509.Certificate, crypto.Signer, error) {
	root, key, err := loadLocalCA()
	if err == nil {
		// Restore the public export if it was accidentally removed.
		err = atomicWrite(filepath.Join(config.DataDir, "ca", "root.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0644)
		return root, key, err
	}
	if !os.IsNotExist(err) {
		return nil, nil, err
	}
	// Do not silently replace a missing private key when clients may still trust
	// the public certificate from an existing installation.
	if _, statErr := os.Stat(filepath.Join(config.DataDir, "ca", "root.crt")); statErr == nil {
		return nil, nil, fmt.Errorf("local CA private bundle is missing; restore ca/root.pem from backup")
	} else if !os.IsNotExist(statErr) {
		return nil, nil, statErr
	}
	key, err = newKey()
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: localCAName}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	certPEM, keyPEM, err := encodeCertificate(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	if err != nil {
		return nil, nil, err
	}
	if err := atomicWrite(filepath.Join(config.DataDir, "ca", "root.pem"), append(certPEM, keyPEM...), 0600); err != nil {
		return nil, nil, err
	}
	if err := atomicWrite(filepath.Join(config.DataDir, "ca", "root.crt"), certPEM, 0644); err != nil {
		return nil, nil, err
	}
	root, err = x509.ParseCertificate(der)
	return root, key, err
}

func issueLocal(ctx context.Context, domain string) (tls.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return tls.Certificate{}, err
	}
	root, caKey, err := ensureLocalCA()
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := newKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	expires := now.Add(90 * 24 * time.Hour)
	if expires.After(root.NotAfter) {
		expires = root.NotAfter
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
