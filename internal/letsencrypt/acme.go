package letsencrypt

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
)

// These small seams let protocol tests use a local ACME test server and prove
// TXT lifetime/order handling without making real CA requests.
var acmeHTTPClient = &http.Client{Timeout: 30 * time.Second}
var checkPropagation = waitForPropagation

func directoryURL() string {
	directory := config.ACMEDirectory
	if directory == "" {
		directory = acme.LetsEncryptURL
	}
	return directory
}

func issueACME(ctx context.Context, domain string) (tls.Certificate, error) {
	directory := directoryURL()
	id := sha256.Sum256([]byte(directory))
	accountKey, err := persistentKey(filepath.Join(config.DataDir, "acme", hex.EncodeToString(id[:16])+".key"))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ACME account key: %w", err)
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: directory, HTTPClient: acmeHTTPClient}
	account := &acme.Account{}
	if config.ACMEEmail != "" {
		account.Contact = []string{"mailto:" + strings.TrimPrefix(config.ACMEEmail, "mailto:")}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return tls.Certificate{}, fmt.Errorf("register ACME account: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create ACME order: %w", err)
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return tls.Certificate{}, err
		}
		if auth.Identifier.Type != "dns" || !strings.EqualFold(auth.Identifier.Value, domain) {
			return tls.Certificate{}, fmt.Errorf("unexpected ACME authorization identifier")
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, candidate := range auth.Challenges {
			if candidate.Type == "dns-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			return tls.Certificate{}, fmt.Errorf("ACME server offered no DNS-01 challenge")
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return tls.Certificate{}, err
		}
		name := "_acme-challenge." + domain
		// Keep TXT until the complete order has finished, including slow CA polls.
		cleanup, err := challengePublisher(ctx, name, value, int(issuanceTimeout()/time.Second)+60)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("publish DNS-01 challenge: %w", err)
		}
		defer cleanupChallenge(cleanup)
		propCtx, cancel := context.WithTimeout(ctx, config.ACMEDNSTimeout)
		err = checkPropagation(propCtx, name, value)
		cancel()
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("DNS-01 propagation failed (delegate %s to this DNSBox and expose UDP/TCP 53): %w", config.Domain, err)
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return tls.Certificate{}, fmt.Errorf("accept DNS-01 challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
			return tls.Certificate{}, fmt.Errorf("validate DNS-01 challenge: %w", err)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("wait for ACME order: %w", err)
	}
	key, err := newKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("finalize ACME order: %w", err)
	}
	if len(chain) == 0 {
		return tls.Certificate{}, fmt.Errorf("ACME server returned an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return tls.Certificate{}, err
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("ACME server returned a certificate outside its validity period")
	}
	cert := tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}
	certPEM, keyPEM, err := encodeCertificate(cert)
	if err != nil {
		return tls.Certificate{}, err
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("ACME certificate does not match requested key: %w", err)
	}
	return cert, nil
}

func waitForPropagation(ctx context.Context, name, value string) error {
	var lastErr error
	for {
		lastErr = queryAuthorities(ctx, name, value)
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%v: %w", lastErr, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

func queryAuthorities(ctx context.Context, name, value string) error {
	servers, err := net.DefaultResolver.LookupNS(ctx, config.Domain)
	if err != nil {
		return fmt.Errorf("look up authoritative nameservers: %w", err)
	}
	if len(servers) == 0 {
		return fmt.Errorf("no authoritative nameservers for %s", config.Domain)
	}
	question := new(dns.Msg)
	question.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	question.RecursionDesired = false
	for _, server := range servers {
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, server.Host)
		if err != nil {
			return fmt.Errorf("resolve nameserver %s: %w", server.Host, err)
		}
		matched := false
		for _, ip := range addresses {
			client := &dns.Client{Timeout: 3 * time.Second}
			address := net.JoinHostPort(ip.IP.String(), "53")
			response, _, err := client.ExchangeContext(ctx, question, address)
			if err == nil && response.Truncated {
				client.Net = "tcp"
				response, _, err = client.ExchangeContext(ctx, question, address)
			}
			if err != nil || response == nil || !response.Authoritative || response.Rcode != dns.RcodeSuccess {
				continue
			}
			for _, rr := range response.Answer {
				if txt, ok := rr.(*dns.TXT); ok && strings.EqualFold(txt.Hdr.Name, dns.Fqdn(name)) && strings.Join(txt.Txt, "") == value {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return fmt.Errorf("nameserver %s does not serve the expected TXT record", server.Host)
		}
	}
	return nil
}
