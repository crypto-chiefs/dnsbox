package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func createCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert: cert, key: key, pool: pool}
}
func nodeSettings(t *testing.T, ca testCA, ip string) (Settings, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "node"}, IPAddresses: []net.IP{net.ParseIP(ip)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	dir := t.TempDir()
	settings := Settings{Listen: "127.0.0.1:9443", Certificate: filepath.Join(dir, "node.crt"), PrivateKey: filepath.Join(dir, "node.key"), CACertificate: filepath.Join(dir, "root.crt")}
	for path, data := range map[string][]byte{settings.Certificate: certPEM, settings.PrivateKey: keyPEM, settings.CACertificate: rootPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return settings, cert
}

type testNode struct {
	server  *httptest.Server
	manager *Manager
	store   *txtstore.Store
}

func makeCluster(t *testing.T, count int, wrap func(int, http.Handler) http.Handler) ([]testNode, testCA) {
	t.Helper()
	if err := config.Load([]string{"--domain=example.test", "--ip=192.168.1.2", "--allowed-cidrs=192.168.0.0/16", "--tls-mode=local"}); err != nil {
		t.Fatal(err)
	}
	ca := createCA(t, "dedicated cluster CA")
	nodes := make([]testNode, count)
	for i := range nodes {
		nodes[i].server = httptest.NewUnstartedServer(nil)
		t.Cleanup(nodes[i].server.Close)
	}
	for i := range nodes {
		settings, _ := nodeSettings(t, ca, "127.0.0.1")
		settings.Listen = nodes[i].server.Listener.Addr().String()
		for j := range nodes {
			if i != j {
				settings.Peers = append(settings.Peers, "https://"+nodes[j].server.Listener.Addr().String())
			}
		}
		manager, err := newManager(settings)
		if err != nil {
			t.Fatal(err)
		}
		store := txtstore.New()
		manager.store = store
		nodes[i].manager = manager
		nodes[i].store = store
		handler := manager.Handler()
		if wrap != nil {
			handler = wrap(i, handler)
		}
		nodes[i].server.Config.Handler = handler
		nodes[i].server.TLS = manager.tlsConfig.Clone()
	}
	for i := range nodes {
		nodes[i].server.StartTLS()
		t.Cleanup(nodes[i].manager.client.CloseIdleConnections)
	}
	return nodes, ca
}
func token(text string) string {
	sum := sha256.Sum256([]byte(text))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const testName = "_acme-challenge.192-168-1-50.example.test"

func TestConcurrentPublishAndExactCleanup(t *testing.T) {
	nodes, _ := makeCluster(t, 3, nil)
	values := []string{token("first order"), token("second order")}
	var wg sync.WaitGroup
	cleanups := make([]func(context.Context) error, 2)
	for i := range cleanups {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			cleanups[i], err = nodes[i].manager.Publish(context.Background(), testName, values[i], 120)
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	for i, node := range nodes {
		if len(node.store.GetAll(testName)) != 2 {
			t.Fatalf("node %d did not store both concurrent challenges", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if cleanups[0] == nil || cleanups[1] == nil {
		t.Fatal("publication failed")
	}
	if err := cleanups[0](ctx); err != nil {
		t.Fatal("cleanup must survive canceled parent:", err)
	}
	for i, node := range nodes {
		if got := node.store.GetAll(testName); !reflect.DeepEqual(got, []string{values[1]}) {
			t.Fatalf("node %d cleanup affected the other order: %v", i, got)
		}
	}
	if err := cleanups[1](context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, node := range nodes {
		if len(node.store.GetAll(testName)) != 0 {
			t.Fatalf("node %d retained completed challenge", i)
		}
	}
}

func TestPartialFailureFailsClosedAndCleansEveryNode(t *testing.T) {
	nodes, _ := makeCluster(t, 3, func(i int, next http.Handler) http.Handler {
		if i != 2 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				http.Error(w, "unavailable", 503)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	other := token("independent order")
	for _, node := range nodes {
		if err := node.store.Add(testName, other, 120); err != nil {
			t.Fatal(err)
		}
	}
	cleanup, err := nodes[0].manager.Publish(context.Background(), testName, token("failed order"), 120)
	if err == nil || cleanup != nil {
		t.Fatal("partial replication reported success")
	}
	for i, node := range nodes {
		if got := node.store.GetAll(testName); !reflect.DeepEqual(got, []string{other}) {
			t.Fatalf("node %d has incorrect post-failure values %v", i, got)
		}
	}
}

func TestCanceledPublishStillRemovesRemoteValues(t *testing.T) {
	var cancel context.CancelFunc
	nodes, _ := makeCluster(t, 3, func(i int, next http.Handler) http.Handler {
		if i != 1 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if r.Method == http.MethodPost {
				cancel()
			}
		})
	})
	ctx, cancelFunc := context.WithCancel(context.Background())
	cancel = cancelFunc
	defer cancel()
	cleanup, err := nodes[0].manager.Publish(ctx, testName, token("canceled order"), 120)
	if err == nil {
		if cleanup == nil {
			t.Fatal("missing cleanup")
		}
		if err := cleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i, node := range nodes {
		if values := node.store.GetAll(testName); len(values) != 0 {
			t.Fatalf("node %d retained canceled values: %v", i, values)
		}
	}
}

func TestMutualTLSAndExplicitPeerIdentity(t *testing.T) {
	nodes, ca := makeCluster(t, 2, nil)
	untrusted := createCA(t, "unrelated CA")
	_, wrongCA := nodeSettings(t, untrusted, "127.0.0.1")
	_, wrongIP := nodeSettings(t, ca, "127.0.0.9")
	original := nodes[0].manager.client.Transport.(*http.Transport).TLSClientConfig
	for name, tlsConfig := range map[string]*tls.Config{
		"no client certificate":      {RootCAs: ca.pool, MinVersion: tls.VersionTLS13},
		"untrusted client CA":        {RootCAs: ca.pool, Certificates: []tls.Certificate{wrongCA}, MinVersion: tls.VersionTLS13},
		"unconfigured peer identity": {RootCAs: ca.pool, Certificates: []tls.Certificate{wrongIP}, MinVersion: tls.VersionTLS13},
		"TLS 1.2":                    {RootCAs: ca.pool, Certificates: original.Certificates, MaxVersion: tls.VersionTLS12},
	} {
		t.Run(name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: tlsConfig}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			response, err := client.Get(nodes[1].server.URL + "/acme-challenge")
			if err == nil {
				response.Body.Close()
				t.Fatal("unauthorized TLS connection succeeded")
			}
		})
	}
	plain := httptest.NewRecorder()
	nodes[1].manager.Handler().ServeHTTP(plain, httptest.NewRequest(http.MethodPost, "/acme-challenge", strings.NewReader("{}")))
	if plain.Code != http.StatusUnauthorized {
		t.Fatal("handler accepted request without verified TLS")
	}
}

func TestRejectsInvalidPayloadsAndNeverRedirects(t *testing.T) {
	var redirected atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(204) }))
	defer trap.Close()
	nodes, _ := makeCluster(t, 2, func(i int, next http.Handler) http.Handler {
		if i != 1 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Test-Redirect") == "yes" {
				http.Redirect(w, r, trap.URL, http.StatusTemporaryRedirect)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	client := nodes[0].manager.client
	for _, payload := range []string{
		`{"fqdn":"_acme-challenge.192-168-1-50.attacker.test","value":"` + token("x") + `","ttl":60}`,
		`{"fqdn":"` + testName + `","value":"not-a-digest","ttl":60}`,
		`{"fqdn":"` + testName + `","value":"` + token("x") + `","ttl":3601}`,
		`{"fqdn":"` + testName + `","value":"` + token("x") + `","ttl":60,"unknown":true}`,
		strings.Repeat("x", 5000),
	} {
		response, err := client.Post(nodes[1].server.URL+"/acme-challenge", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("invalid payload returned %d", response.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, nodes[1].server.URL+"/acme-challenge", strings.NewReader("{}"))
	req.Header.Set("X-Test-Redirect", "yes")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 307 || redirected.Load() != 0 {
		t.Fatal("cluster client followed a redirect")
	}
}

func TestLoadValidatesConfigurationAndDedicatedTrust(t *testing.T) {
	ca := createCA(t, "cluster CA")
	settings, _ := nodeSettings(t, ca, "127.0.0.1")
	settings.Peers = []string{"https://127.0.0.1:9444"}
	path := filepath.Join(filepath.Dir(settings.Certificate), "cluster.json")
	relative := settings
	relative.Certificate = filepath.Base(settings.Certificate)
	relative.PrivateKey = filepath.Base(settings.PrivateKey)
	relative.CACertificate = filepath.Base(settings.CACertificate)
	data, _ := json.Marshal(relative)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"http://127.0.0.1:9444", "https://hostname.example:9444", "https://127.0.0.1:9444/path", "https://127.0.0.1:9444?x=y", "https://user:password@127.0.0.1:9444", "https://127.0.0.1:9443", "https://[::ffff:0.0.0.0]:9444", "https://255.255.255.255:9444", "https://169.254.1.1:9444", "https://[fe80::1]:9444"} {
		candidate := settings
		candidate.Peers = []string{peer}
		if _, err := newManager(candidate); err == nil {
			t.Fatalf("accepted invalid peer %s", peer)
		}
	}
	candidate := settings
	candidate.Listen = "0.0.0.0:9443"
	candidate.Peers = []string{"https://127.0.0.1:9443"}
	if _, err := newManager(candidate); err == nil {
		t.Fatal("accepted this node as a peer through its wildcard listener")
	}
	candidate = settings
	candidate.Peers = make([]string, 9)
	if _, err := newManager(candidate); err == nil {
		t.Fatal("accepted more than eight peers")
	}
	candidate = settings
	candidate.Peers = []string{settings.Peers[0], settings.Peers[0]}
	if _, err := newManager(candidate); err == nil {
		t.Fatal("accepted duplicate peers")
	}
	bad := bytes.TrimSuffix(data, []byte("}"))
	bad = append(bad, []byte(`,"unknown":true}`)...)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted unknown configuration field")
	}
	if err := os.WriteFile(path, append(data, bytes.Repeat([]byte(" "), 64<<10)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted oversized configuration")
	}
}

func TestServeReadyBindsBeforeSignalingAndShutsDown(t *testing.T) {
	nodes, _ := makeCluster(t, 2, nil)
	manager := nodes[0].manager
	blockedReady := make(chan struct{})
	if err := manager.ServeReady(context.Background(), blockedReady); err == nil {
		t.Fatal("binding an occupied listener succeeded")
	}
	select {
	case <-blockedReady:
		t.Fatal("readiness was signaled after a bind failure")
	default:
	}
	nodes[0].server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- manager.ServeReady(ctx, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("server failed before readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not report readiness")
	}
	cleanup, err := nodes[1].manager.Publish(context.Background(), testName, token("ready"), 60)
	if err != nil {
		t.Fatal("ready server did not accept authenticated replication:", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
	listener, err := net.Listen("tcp", manager.listen)
	if err != nil {
		t.Fatal("server left its listener open:", err)
	}
	listener.Close()
}

func TestClientRejectsUntrustedOrWrongIdentityServer(t *testing.T) {
	nodes, ca := makeCluster(t, 2, nil)
	foreign := createCA(t, "untrusted server CA")
	for _, tc := range []struct {
		name string
		ca   testCA
		ip   string
	}{{"untrusted CA", foreign, "127.0.0.1"}, {"wrong IP", ca, "127.0.0.9"}} {
		t.Run(tc.name, func(t *testing.T) {
			_, certificate := nodeSettings(t, tc.ca, tc.ip)
			var received atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			manager := nodes[0].manager
			original := manager.peers
			manager.peers = []string{server.URL}
			defer func() { manager.peers = original }()
			if cleanup, err := manager.Publish(context.Background(), testName, token(tc.name), 60); err == nil || cleanup != nil {
				t.Fatal("replicated to a server without the expected dedicated CA and IP identity")
			}
			if received.Load() != 0 || len(nodes[0].store.GetAll(testName)) != 0 {
				t.Fatal("failed authentication exposed a challenge or retained its local value")
			}
		})
	}
}
