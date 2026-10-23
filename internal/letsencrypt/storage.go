package letsencrypt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"golang.org/x/crypto/acme"
)

const localCAName = "DNSBox Local CA"

func certificateSource() []byte {
	source := config.TLSMode
	if config.TLSMode == "acme" {
		source += " " + directoryURL()
	}
	return []byte("# DNSBox certificate source: " + source + "\n")
}

// LoadCertificate reads the atomic bundle, with a read-only migration path for
// pre-0.5 ACME certificates. Merely checking a certificate never issues one.
func LoadCertificate(domain string) (tls.Certificate, error) {
	domain, err := config.ValidateHostname(domain)
	if err != nil {
		return tls.Certificate{}, err
	}
	data, err := os.ReadFile(filepath.Join(cacheDirectory(), domain+".pem"))
	var cert tls.Certificate
	if err == nil {
		if !bytes.HasPrefix(data, certificateSource()) {
			return tls.Certificate{}, fmt.Errorf("certificate source changed; reissuance required")
		}
		cert, err = tls.X509KeyPair(data, data)
	} else if os.IsNotExist(err) && config.TLSMode == "acme" && directoryURL() == acme.LetsEncryptURL {
		exported, readErr := os.ReadFile(filepath.Join(config.DataDir, "certs", domain+".crt"))
		if readErr != nil {
			return tls.Certificate{}, readErr
		}
		if bytes.HasPrefix(exported, []byte("# DNSBox certificate source:")) && !bytes.HasPrefix(exported, certificateSource()) {
			return tls.Certificate{}, fmt.Errorf("exported certificate source changed; reissuance required")
		}
		cert, err = tls.LoadX509KeyPair(filepath.Join(config.DataDir, "certs", domain+".crt"), filepath.Join(config.DataDir, "certs", domain+".key"))
		if err == nil && len(cert.Certificate) < 2 {
			return tls.Certificate{}, fmt.Errorf("legacy certificate has no intermediate chain; reissuance required")
		}
	}
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, fmt.Errorf("empty certificate chain")
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := cert.Leaf.VerifyHostname(domain); err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate outside validity period")
	}
	if config.TLSMode == "local" {
		root, _, err := loadLocalCA()
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := cert.Leaf.CheckSignatureFrom(root); err != nil {
			return tls.Certificate{}, fmt.Errorf("certificate belongs to a different local CA: %w", err)
		}
	} else if cert.Leaf.Issuer.CommonName == localCAName {
		return tls.Certificate{}, fmt.Errorf("local CA certificate cannot be used in ACME mode")
	}
	return cert, nil
}

func encodeCertificate(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	if len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("empty certificate chain")
	}
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func saveCertificate(domain string, cert tls.Certificate) error {
	certPEM, keyPEM, err := encodeCertificate(cert)
	if err != nil {
		return err
	}
	// Exports are individually atomic. Consumers requiring one atomic snapshot
	// should use the combined PEM bundle, which is committed last.
	dir := filepath.Join(config.DataDir, "certs")
	if err := atomicWrite(filepath.Join(dir, domain+".key"), keyPEM, 0600); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, domain+".crt"), append(certificateSource(), certPEM...), 0600); err != nil {
		return err
	}
	bundle := append(certificateSource(), certPEM...)
	bundle = append(bundle, keyPEM...)
	return atomicWrite(filepath.Join(cacheDirectory(), domain+".pem"), bundle, 0600)
}

// The old daemon only used Let's Encrypt production. Adopt complete, still
// valid legacy chains into the new cache so unattended renewals include them.
// Leaf-only legacy certificates are reissued on first use or explicit --issue.
func migrateLegacyCertificates(ctx context.Context) error {
	if config.TLSMode != "acme" || directoryURL() != acme.LetsEncryptURL {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(config.DataDir, "certs"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		domain := strings.TrimSuffix(entry.Name(), ".crt")
		canonical, err := config.ValidateHostname(domain)
		if err != nil || canonical != domain {
			continue
		}
		if _, err := os.Stat(filepath.Join(cacheDirectory(), domain+".pem")); !os.IsNotExist(err) {
			continue
		}
		release, err := acquireIssuer(ctx)
		if err != nil {
			return err
		}
		cert, err := LoadCertificate(domain)
		if err != nil {
			release()
			// Invalid or incomplete old certificates must not prevent renewal of
			// the other cache entries. They are handled by the on-demand path.
			continue
		}
		err = saveCertificate(domain, cert)
		release()
		if err != nil {
			return fmt.Errorf("migrate legacy certificate %s: %w", domain, err)
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".dnsbox-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func readSigningKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key file %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type")
	}
	return signer, nil
}

func persistentKey(path string) (crypto.Signer, error) {
	key, err := readSigningKey(path)
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key, err = newKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return key, nil
}
