package letsencrypt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"golang.org/x/crypto/acme"
)

var cacheDir = "/var/lib/dnsbox/certs"

func IssueCertificate(domain string) (tls.Certificate, error) {
	ctx := context.Background()

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	client := &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
		Key:          accountKey,
	}

	email := "mailto:" + normalizeDomainForEmail(domain) + "@" + config.Domain
	acct := &acme.Account{Contact: []string{email}}
	_, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && !strings.Contains(err.Error(), "already registered") {
		return tls.Certificate{}, fmt.Errorf("register failed: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("authorize order: %w", err)
	}

	var chal *acme.Challenge
	var authURL string
	for _, auth := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, auth)
		if err != nil {
			return tls.Certificate{}, err
		}
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				authURL = authz.URI
				break
			}
		}
	}
	if chal == nil {
		return tls.Certificate{}, fmt.Errorf("no dns-01 challenge found")
	}

	token := chal.Token
	dnsName := "_acme-challenge." + domain
	dnsValue, err := client.DNS01ChallengeRecord(token)
	if err != nil {
		return tls.Certificate{}, err
	}

	txtstore.Set(dnsName, dnsValue, 60)
	logger.Info("[letsencrypt] TXT record set for %s => %s", dnsName, dnsValue)

	_, err = client.Accept(ctx, chal)
	if err != nil {
		txtstore.Delete(dnsName)
		logger.Warn("[letsencrypt] ❌ Accept failed — TXT deleted for %s", dnsName)
		return tls.Certificate{}, err
	}

	_, err = client.WaitAuthorization(ctx, authURL)
	if err != nil {
		txtstore.Delete(dnsName)
		logger.Warn("[letsencrypt] ❌ Authorization failed — TXT deleted for %s", dnsName)
		return tls.Certificate{}, err
	}

	txtstore.Delete(dnsName)
	logger.Info("[letsencrypt] ✅ TXT record deleted for %s", dnsName)

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create cert
	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrBytes, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	logger.Info("[letsencrypt] 🔐 cert created for %s (%d bytes)", domain, len(certDER[0]))

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER[0]})
	keyPEM, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPEM})

	// Ensure directory exists
	logger.Info("[letsencrypt] creating cache dir %s", cacheDir)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		logger.Error("[letsencrypt] ❌ failed to create dir %s: %v", cacheDir, err)
		return tls.Certificate{}, err
	}

	crtPath := filepath.Join(cacheDir, domain+".crt")
	keyPath := filepath.Join(cacheDir, domain+".key")

	if err := os.WriteFile(crtPath, certPEM, 0600); err != nil {
		logger.Error("[letsencrypt] ❌ failed to write cert to %s: %v", crtPath, err)
		return tls.Certificate{}, err
	}
	logger.Info("[letsencrypt] ✅ cert saved to %s", crtPath)

	if err := os.WriteFile(keyPath, keyPEMBytes, 0600); err != nil {
		logger.Error("[letsencrypt] ❌ failed to write key to %s: %v", keyPath, err)
		return tls.Certificate{}, err
	}
	logger.Info("[letsencrypt] ✅ key saved to %s", keyPath)

	return tls.X509KeyPair(certPEM, keyPEMBytes)
}

func HasCertificate(domain string) bool {
	crt := filepath.Join(cacheDir, domain+".crt")
	key := filepath.Join(cacheDir, domain+".key")
	_, err1 := os.Stat(crt)
	_, err2 := os.Stat(key)
	if err1 != nil || err2 != nil {
		return false
	}

	if !IsCertificateValid(domain) {
		logger.Warn("[letsencrypt] certificate for %s is invalid or expired, reissuing...", domain)
		_, err := IssueCertificate(domain)
		if err != nil {
			logger.Error("[letsencrypt] failed to reissue cert for %s: %v", domain, err)
			return false
		}
	}

	return true
}

func IsCertificateValid(domain string) bool {
	certPath := filepath.Join(cacheDir, domain+".crt")
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	now := time.Now()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter)
}

func LoadCertificate(domain string) (tls.Certificate, error) {
	crtPath := filepath.Join(cacheDir, domain+".crt")
	keyPath := filepath.Join(cacheDir, domain+".key")

	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load cert or key for %s: %w", domain, err)
	}

	return cert, nil
}

func normalizeDomainForEmail(domain string) string {
	host := strings.Split(domain, ".")[0]
	ipStr := strings.ReplaceAll(host, "-", ":")

	if ip := net.ParseIP(ipStr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return fmt.Sprintf("ip-%s-%s-%s-%s", ip4[0], ip4[1], ip4[2], ip4[3])
		}
		clean := strings.ReplaceAll(ip.String(), ":", "-")
		return "ipv6-" + clean
	}

	clean := strings.ReplaceAll(domain, ".", "-")
	return "domain-" + clean
}
