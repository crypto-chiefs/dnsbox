// Package cluster replicates only short-lived DNS-01 values between explicitly
// configured peers. It never reads, serves, or transfers certificate keys.
package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/httpserver"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
)

const MaxPeers = 8
const MaxTTL = 3600
const CleanupTimeout = 10 * time.Second

type Settings struct {
	Listen        string   `json:"listen"`
	Certificate   string   `json:"certificate"`
	PrivateKey    string   `json:"private_key"`
	CACertificate string   `json:"ca_certificate"`
	Peers         []string `json:"peers"`
}

type challengeStore interface {
	Add(string, string, int) error
	DeleteValue(string, string)
}
type sharedStore struct{}

func (sharedStore) Add(name, value string, ttl int) error { return txtstore.Add(name, value, ttl) }
func (sharedStore) DeleteValue(name, value string)        { txtstore.DeleteValue(name, value) }

type Manager struct {
	listen       string
	peers        []string
	client       *http.Client
	tlsConfig    *tls.Config
	store        challengeStore
	requests     chan struct{}
	publications chan struct{}
}

type challenge struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// Load validates the complete configuration and credentials before any listener
// starts. Certificate paths may be relative to the JSON configuration file.
func Load(path string) (*Manager, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("cluster configuration is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var settings Settings
	if err := decoder.Decode(&settings); err != nil {
		return nil, fmt.Errorf("cluster configuration: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("cluster configuration must contain one JSON object")
	}
	for _, field := range []*string{&settings.Certificate, &settings.PrivateKey, &settings.CACertificate} {
		if *field == "" {
			return nil, fmt.Errorf("cluster certificate, private_key, and ca_certificate are required")
		}
		if !filepath.IsAbs(*field) {
			*field = filepath.Join(filepath.Dir(path), *field)
		}
	}
	return newManager(settings)
}

func literalAddress(address string, allowUnspecified bool) (netip.Addr, int, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("expected literal IP:port: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, 0, fmt.Errorf("invalid literal cluster IP %q", host)
	}
	ip = ip.Unmap()
	if !(allowUnspecified && ip.IsUnspecified()) && !ip.IsGlobalUnicast() && !ip.IsLoopback() {
		return netip.Addr{}, 0, fmt.Errorf("cluster IP must be unicast or loopback")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return netip.Addr{}, 0, fmt.Errorf("invalid cluster port")
	}
	return ip, port, nil
}

func newManager(settings Settings) (*Manager, error) {
	listenIP, listenPort, err := literalAddress(settings.Listen, true)
	if err != nil {
		return nil, fmt.Errorf("cluster listen: %w", err)
	}
	if len(settings.Peers) > MaxPeers {
		return nil, fmt.Errorf("cluster supports at most %d peers", MaxPeers)
	}
	peers := make([]string, 0, len(settings.Peers))
	seen := make(map[string]bool)
	peerIPs := make(map[netip.Addr]bool)
	for _, raw := range settings.Peers {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
			return nil, fmt.Errorf("cluster peer must be an HTTPS literal-IP URL without path, credentials, query, or fragment")
		}
		ip, port, err := literalAddress(u.Host, false)
		if err != nil {
			return nil, fmt.Errorf("cluster peer: %w", err)
		}
		if ip == listenIP && port == listenPort {
			return nil, fmt.Errorf("cluster peers must exclude this listener")
		}
		canonical := "https://" + net.JoinHostPort(ip.String(), strconv.Itoa(port))
		if seen[canonical] {
			return nil, fmt.Errorf("duplicate cluster peer %s", canonical)
		}
		seen[canonical] = true
		peerIPs[ip] = true
		peers = append(peers, canonical)
	}
	cert, err := tls.LoadX509KeyPair(settings.Certificate, settings.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cluster node certificate: %w", err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	// A wildcard bind still must not publish to this node through one of its
	// certificate addresses. Distinct ports remain usable for local clusters.
	for _, raw := range peers {
		peer, _ := url.Parse(raw)
		ip, port, _ := literalAddress(peer.Host, false)
		if port != listenPort {
			continue
		}
		for _, ownIP := range cert.Leaf.IPAddresses {
			if address, ok := netip.AddrFromSlice(ownIP); ok && ip == address.Unmap() {
				return nil, fmt.Errorf("cluster peers must exclude this node's certificate addresses on the listener port")
			}
		}
	}
	caPEM, err := os.ReadFile(settings.CACertificate)
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(caPEM)) > 0 {
		block, rest := pem.Decode(caPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("cluster CA file must contain only PEM CA certificates")
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("invalid cluster CA certificate")
		}
		roots.AddCert(root)
		count++
		caPEM = rest
	}
	if count == 0 {
		return nil, fmt.Errorf("cluster CA file contains no certificates")
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(intermediate)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth && !listenIP.IsUnspecified() {
			opts.DNSName = listenIP.String()
		}
		if _, err := cert.Leaf.Verify(opts); err != nil {
			return nil, fmt.Errorf("cluster certificate must be valid for server and client authentication: %w", err)
		}
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	serverTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return fmt.Errorf("cluster peer authentication required")
		}
		for _, ip := range state.PeerCertificates[0].IPAddresses {
			if addr, ok := netip.AddrFromSlice(ip); ok && peerIPs[addr.Unmap()] {
				return nil
			}
		}
		return fmt.Errorf("cluster client certificate does not identify a configured peer IP")
	}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: clientTLS, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 4, MaxIdleConns: MaxPeers, MaxIdleConnsPerHost: 2, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Manager{listen: settings.Listen, peers: peers, client: client, tlsConfig: serverTLS, store: sharedStore{}, requests: make(chan struct{}, 32), publications: make(chan struct{}, 16)}, nil
}

func validateChallenge(request challenge) (challenge, error) {
	name := strings.ToLower(strings.TrimSuffix(request.FQDN, "."))
	host := strings.TrimPrefix(name, "_acme-challenge.")
	if host == name {
		return request, fmt.Errorf("expected ACME challenge name")
	}
	canonical, err := config.ValidateHostname(host)
	if err != nil {
		return request, fmt.Errorf("invalid cluster challenge host: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(request.Value)
	if err != nil || len(raw) != 32 || len(request.Value) != 43 || base64.RawURLEncoding.EncodeToString(raw) != request.Value {
		return request, fmt.Errorf("challenge value must be a canonical SHA-256 base64url value")
	}
	if request.TTL < 1 || request.TTL > MaxTTL {
		return request, fmt.Errorf("challenge TTL must be 1..%d", MaxTTL)
	}
	request.FQDN = "_acme-challenge." + canonical
	return request, nil
}

func (m *Manager) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || m.tlsConfig.VerifyConnection(*r.TLS) != nil {
			http.Error(w, "mutual TLS required", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/acme-challenge" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			w.Header().Set("Allow", "POST, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		select {
		case m.requests <- struct{}{}:
			defer func() { <-m.requests }()
		default:
			http.Error(w, "cluster busy", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request challenge
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "expected one JSON object", http.StatusBadRequest)
			return
		}
		request, err := validateChallenge(request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodDelete {
			m.store.DeleteValue(request.FQDN, request.Value)
		} else {
			if err := r.Context().Err(); err != nil {
				http.Error(w, "request canceled", http.StatusRequestTimeout)
				return
			}
			if err := m.store.Add(request.FQDN, request.Value, request.TTL); err != nil {
				http.Error(w, "challenge store unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (m *Manager) Serve(ctx context.Context) error {
	return m.ServeReady(ctx, nil)
}

// ServeReady closes ready after binding the listener. A bind failure returns
// without closing ready, allowing startup to fail before issuance begins.
// The caller must provide a fresh channel for each invocation, or nil.
func (m *Manager) ServeReady(ctx context.Context, ready chan<- struct{}) error {
	defer m.client.CloseIdleConnections()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", m.listen)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		listener.Close()
		return err
	}
	server := &http.Server{Addr: m.listen, Handler: m.Handler(), TLSConfig: m.tlsConfig, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	if ready != nil {
		close(ready)
	}
	return httpserver.ServeListener(ctx, server, listener, true)
}

func (m *Manager) send(ctx context.Context, peer, method string, request challenge) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, peer+"/acme-challenge", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("peer %s: %w", peer, err)
	}
	defer response.Body.Close()
	n, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
	if readErr != nil || n > 4096 {
		return fmt.Errorf("invalid cluster response from %s", peer)
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("peer %s returned HTTP %d", peer, response.StatusCode)
	}
	return nil
}

func (m *Manager) fanout(ctx context.Context, method string, request challenge) error {
	results := make(chan error, len(m.peers))
	for _, peer := range m.peers {
		go func(peer string) { results <- m.send(ctx, peer, method, request) }(peer)
	}
	var errs []error
	for range m.peers {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Publish returns only after every peer has stored the value. On any failure it
// removes that exact value from all peers, including peers with uncertain POST
// outcomes. Cleanup uses a fresh bounded context and never deletes other orders.
func (m *Manager) Publish(ctx context.Context, name, value string, ttlSeconds int) (func(context.Context) error, error) {
	request, err := validateChallenge(challenge{FQDN: name, Value: value, TTL: ttlSeconds})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case m.publications <- struct{}{}:
		defer func() { <-m.publications }()
	default:
		return nil, fmt.Errorf("cluster publication queue is full")
	}
	if err := m.store.Add(request.FQDN, request.Value, request.TTL); err != nil {
		return nil, err
	}
	var once sync.Once
	var cleanupErr error
	cleanup := func(parent context.Context) error {
		once.Do(func() {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), CleanupTimeout)
			defer cancel()
			m.store.DeleteValue(request.FQDN, request.Value)
			cleanupErr = m.fanout(cleanupCtx, http.MethodDelete, request)
		})
		return cleanupErr
	}
	if err := m.fanout(ctx, http.MethodPost, request); err != nil {
		return nil, errors.Join(err, cleanup(context.Background()))
	}
	return cleanup, nil
}
