// Package letsencrypt manages on-demand ACME and private-network certificates.
package letsencrypt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
)

// One issuer serializes account/CA initialization and renewal. Certificates
// already on disk never wait for the issuer.
var issuer = make(chan struct{}, 1)
var pendingRequests = make(chan struct{}, 64)
var failureMu sync.Mutex
var failures = make(map[string]failure)

type failure struct {
	err   error
	until time.Time
}

func cacheDirectory() string        { return filepath.Join(config.DataDir, "certs", config.TLSMode) }
func cacheKey(domain string) string { return filepath.Join(cacheDirectory(), domain) }

// GetCertificate validates ownership before accessing disk or contacting a CA.
// Valid certificates stay available while the service-owned RenewCached worker
// handles renewal. No detached goroutine can outlive the data-directory lock.
func GetCertificate(ctx context.Context, domain string) (tls.Certificate, error) {
	domain, err := config.ValidateHostname(domain)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert, err := LoadCertificate(domain); err == nil {
		return cert, nil
	}
	release, err := acquireIssuer(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer release()
	return refreshLocked(ctx, domain)
}

func acquireIssuer(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case pendingRequests <- struct{}{}:
	default:
		return nil, fmt.Errorf("certificate request queue is full; retry later")
	}
	select {
	case issuer <- struct{}{}:
		return func() { <-issuer; <-pendingRequests }, nil
	case <-ctx.Done():
		<-pendingRequests
		return nil, ctx.Err()
	}
}

func issuanceTimeout() time.Duration { return config.ACMEDNSTimeout + 3*time.Minute }

// IssueCertificate is retained for callers of the original API. It completes
// any due renewal and refreshes exports before returning.
func IssueCertificate(domain string) (tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), issuanceTimeout())
	defer cancel()
	return IssueCertificateContext(ctx, domain)
}

// IssueCertificateContext is the synchronous CLI/export path. Unlike the TLS
// callback it finishes any due renewal before a one-shot process can exit.
func IssueCertificateContext(ctx context.Context, domain string) (tls.Certificate, error) {
	domain, err := config.ValidateHostname(domain)
	if err != nil {
		return tls.Certificate{}, err
	}
	release, err := acquireIssuer(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer release()
	cert, err := refreshLocked(ctx, domain)
	if err != nil {
		return tls.Certificate{}, err
	}
	if config.TLSMode == "local" {
		if _, _, err := ensureLocalCA(); err != nil {
			return tls.Certificate{}, err
		}
	}
	if err := saveCertificate(domain, cert); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// refreshLocked requires the issuer token. It rechecks disk after waiting so
// concurrent first handshakes share one certificate rather than many orders.
func refreshLocked(ctx context.Context, domain string) (tls.Certificate, error) {
	cached, loadErr := LoadCertificate(domain)
	if loadErr == nil && !needsRenewal(cached, time.Now()) {
		return cached, nil
	}
	key := cacheKey(domain)
	failureMu.Lock()
	previous := failures[key]
	failureMu.Unlock()
	if time.Now().Before(previous.until) {
		return tls.Certificate{}, fmt.Errorf("certificate request cooling down: %w", previous.err)
	}
	ctx, cancel := context.WithTimeout(ctx, issuanceTimeout())
	defer cancel()
	var cert tls.Certificate
	var err error
	switch config.TLSMode {
	case "local":
		cert, err = issueLocal(ctx, domain)
	case "acme":
		cert, err = issueACME(ctx, domain)
	default:
		err = fmt.Errorf("unsupported TLS mode %q", config.TLSMode)
	}
	if err == nil {
		err = saveCertificate(domain, cert)
	}
	failureMu.Lock()
	if err != nil && !errors.Is(err, context.Canceled) {
		// Bound memory even when arbitrary hostnames are repeatedly requested.
		if len(failures) >= 256 {
			for k, v := range failures {
				if !time.Now().Before(v.until) {
					delete(failures, k)
				}
			}
			if len(failures) >= 256 {
				for k := range failures {
					delete(failures, k)
					break
				}
			}
		}
		failures[key] = failure{err: err, until: time.Now().Add(time.Minute)}
	} else {
		delete(failures, key)
	}
	failureMu.Unlock()
	return cert, err
}

func needsRenewal(cert tls.Certificate, now time.Time) bool {
	if cert.Leaf == nil {
		return true
	}
	window := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) / 3
	if window > 30*24*time.Hour {
		window = 30 * 24 * time.Hour
	}
	return !now.Add(window).Before(cert.Leaf.NotAfter)
}

func HasCertificate(domain string) bool     { _, err := LoadCertificate(domain); return err == nil }
func IsCertificateValid(domain string) bool { return HasCertificate(domain) }

// RenewCached refreshes due certificates even if no client is currently using
// them. Call periodically with the service lifetime context.
func RenewCached(ctx context.Context) error {
	if err := migrateLegacyCertificates(ctx); err != nil {
		return err
	}
	entries, err := os.ReadDir(cacheDirectory())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		domain := strings.TrimSuffix(entry.Name(), ".pem")
		if _, err := config.ValidateHostname(domain); err != nil {
			continue
		}
		if cert, err := LoadCertificate(domain); err == nil && !needsRenewal(cert, time.Now()) {
			continue
		}
		select {
		case issuer <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		_, err := refreshLocked(ctx, domain)
		<-issuer
		if err != nil {
			logger.Warn("scheduled certificate renewal for %s: %v", domain, err)
		}
	}
	return nil
}
