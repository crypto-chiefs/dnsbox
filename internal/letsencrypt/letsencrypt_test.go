package letsencrypt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
)

func configureTest(t *testing.T, mode string) {
	t.Helper()
	if err := config.Load([]string{"--domain=example.test", "--ip=192.168.1.2", "--tls-mode=" + mode, "--allowed-cidrs=192.168.0.0/16", "--data-dir=" + t.TempDir(), "--acme-dns-timeout=1s"}); err != nil {
		t.Fatal(err)
	}
	failureMu.Lock()
	failures = make(map[string]failure)
	failureMu.Unlock()
	t.Cleanup(func() { issuer <- struct{}{}; <-issuer })
}

func TestLocalCAConcurrentIssuancePersistenceAndExports(t *testing.T) {
	configureTest(t, "local")
	const domain = "192-168-1-10.example.test"
	var wg sync.WaitGroup
	results := make(chan tls.Certificate, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, err := GetCertificate(context.Background(), domain)
			if err != nil {
				t.Error(err)
				return
			}
			results <- cert
		}()
	}
	wg.Wait()
	close(results)
	var first tls.Certificate
	for cert := range results {
		if first.Leaf == nil {
			first = cert
		}
		if !bytes.Equal(first.Certificate[0], cert.Certificate[0]) {
			t.Fatal("concurrent callers received different certificates")
		}
	}
	if first.Leaf == nil {
		t.Fatal("no certificate issued")
	}
	rootPEM, err := os.ReadFile(filepath.Join(config.DataDir, "ca", "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid public CA export")
	}
	if _, err := first.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: domain}); err != nil {
		t.Fatalf("local certificate is not trusted by exported CA: %v", err)
	}
	exported, err := tls.LoadX509KeyPair(filepath.Join(config.DataDir, "certs", domain+".crt"), filepath.Join(config.DataDir, "certs", domain+".key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exported.Certificate[0], first.Certificate[0]) {
		t.Fatal("certificate export mismatch")
	}
	second, err := GetCertificate(context.Background(), "192.168.1.11.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "192.168.1.11.example.test"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(config.DataDir, "ca", "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootPEM, after) {
		t.Fatal("CA changed across issuance")
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(config.DataDir, "ca", "root.pem"), filepath.Join(config.DataDir, "certs", domain+".key"), filepath.Join(cacheDirectory(), domain+".pem")} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("%s has unsafe mode %o", p, info.Mode().Perm())
			}
		}
	}
}

func TestInvalidNamesAndModeIsolation(t *testing.T) {
	configureTest(t, "local")
	for _, name := range []string{"../../outside", "192-168-1-10.attacker.test", "192-168-1-10.example.test.attacker.test", "127-0-0-1.example.test", ""} {
		if _, err := GetCertificate(context.Background(), name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	const domain = "192-168-1-10.example.test"
	if _, err := GetCertificate(context.Background(), domain); err != nil {
		t.Fatal(err)
	}
	config.TLSMode = "acme"
	if HasCertificate(domain) {
		t.Fatal("local CA export reused as an ACME certificate")
	}
	config.TLSMode = "local"
	if err := os.WriteFile(filepath.Join(cacheDirectory(), domain+".pem"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if HasCertificate(domain) {
		t.Fatal("corrupt cached certificate accepted")
	}
}

func TestMissingLocalPrivateCAIsNotReplaced(t *testing.T) {
	configureTest(t, "local")
	if _, err := GetCertificate(context.Background(), "192-168-1-10.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(config.DataDir, "ca", "root.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := GetCertificate(context.Background(), "192-168-1-11.example.test"); err == nil {
		t.Fatal("silently replaced missing local CA")
	}
}

func TestScheduledRenewalKeepsValidCacheAndPersistsReplacement(t *testing.T) {
	configureTest(t, "local")
	const domain = "192-168-1-10.example.test"
	cert, err := GetCertificate(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	root, key, err := loadLocalCA()
	if err != nil {
		t.Fatal(err)
	}
	template := *cert.Leaf
	template.NotBefore = time.Now().Add(-89 * 24 * time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &template, root, cert.Leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate[0] = der
	cert.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveCertificate(domain, cert); err != nil {
		t.Fatal(err)
	}
	returned, err := GetCertificate(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(returned.Certificate[0], der) {
		t.Fatal("valid cache was not returned immediately")
	}
	if err := RenewCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	renewed, err := LoadCertificate(domain)
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.Leaf.NotAfter.After(template.NotAfter) {
		t.Fatal("certificate was not renewed")
	}
}

func TestCancelledWaitAndPureHasCertificate(t *testing.T) {
	configureTest(t, "local")
	const domain = "192-168-1-10.example.test"
	if HasCertificate(domain) {
		t.Fatal("unexpected cached certificate")
	}
	if _, err := os.Stat(filepath.Join(config.DataDir, "ca")); !os.IsNotExist(err) {
		t.Fatal("HasCertificate generated state")
	}
	issuer <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := GetCertificate(ctx, domain)
	<-issuer
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestFullChainEncoding(t *testing.T) {
	configureTest(t, "local")
	cert, err := GetCertificate(context.Background(), "192-168-1-10.example.test")
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := loadLocalCA()
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate = append(cert.Certificate, root.Raw)
	data, _, err := encodeCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		count++
		data = rest
	}
	if count != 2 {
		t.Fatalf("encoded %d certificates, want full chain of 2", count)
	}
}

func TestExplicitIssueRepairsExportsAndLocalCAFile(t *testing.T) {
	configureTest(t, "local")
	const domain = "192-168-1-10.example.test"
	cert, err := IssueCertificateContext(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.DataDir, "certs", domain+".crt"), []byte("obsolete mode export"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(config.DataDir, "ca", "root.crt")); err != nil {
		t.Fatal(err)
	}
	reissued, err := IssueCertificateContext(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Certificate[0], reissued.Certificate[0]) {
		t.Fatal("needlessly reissued a valid certificate")
	}
	exported, err := tls.LoadX509KeyPair(filepath.Join(config.DataDir, "certs", domain+".crt"), filepath.Join(config.DataDir, "certs", domain+".key"))
	if err != nil || !bytes.Equal(exported.Certificate[0], cert.Certificate[0]) {
		t.Fatalf("failed to repair certificate export: %v", err)
	}
	if _, err := os.Stat(filepath.Join(config.DataDir, "ca", "root.crt")); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalFailureRetainsStillValidCertificate(t *testing.T) {
	configureTest(t, "local")
	const domain = "192-168-1-10.example.test"
	cert, err := IssueCertificateContext(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	root, key, err := loadLocalCA()
	if err != nil {
		t.Fatal(err)
	}
	template := *cert.Leaf
	template.NotBefore = time.Now().Add(-89 * 24 * time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &template, root, cert.Leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate[0] = der
	cert.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveCertificate(domain, cert); err != nil {
		t.Fatal(err)
	}
	// A failed write of the public CA export must not break an existing leaf.
	rootExport := filepath.Join(config.DataDir, "ca", "root.crt")
	if err := os.Remove(rootExport); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootExport, 0700); err != nil {
		t.Fatal(err)
	}
	issuer <- struct{}{}
	_, err = refreshLocked(context.Background(), domain)
	<-issuer
	if err == nil {
		t.Fatal("failed renewal must report its error")
	}
	retained, err := GetCertificate(context.Background(), domain)
	if err != nil {
		t.Fatalf("failed renewal made valid cached certificate unavailable: %v", err)
	}
	if !bytes.Equal(retained.Certificate[0], der) {
		t.Fatal("did not retain the valid certificate")
	}
	if !HasCertificate(domain) {
		t.Fatal("failed renewal damaged existing certificate")
	}
}
