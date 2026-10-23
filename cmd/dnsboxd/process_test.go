package main

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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/cluster"
	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/miekg/dns"
)

// The test executable runs the real daemon entry point in a separate process,
// including signal handling, data-directory locking and all service listeners.
func TestDaemonProcessHelper(t *testing.T) {
	if os.Getenv("DNSBOX_TEST_HELPER") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("DNSBOX_TEST_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
}

type processOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *processOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *processOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func daemonCommand(t *testing.T, args []string) *exec.Cmd {
	t.Helper()
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonProcessHelper$", "-test.timeout=30s")
	// External DNSBox settings must not change the subprocess configuration.
	for _, item := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(item), "DNSBOX_") {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, "DNSBOX_TEST_HELPER=1", "DNSBOX_TEST_ARGS="+string(data))
	return cmd
}

func reserveDNSAddress(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := tcp.Addr().String()
		udp, err := net.ListenPacket("udp", address)
		if err == nil {
			udp.Close()
			tcp.Close()
			return address
		}
		tcp.Close()
	}
	t.Fatal("could not find a free TCP/UDP port pair")
	return ""
}

func TestDaemonProcessPrivateNetwork(t *testing.T) {
	var backendCalls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls.Add(1)
		fmt.Fprintf(w, "backend %s %s", r.Host, r.URL.RequestURI())
	}))
	defer backend.Close()
	_, backendPort, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	dnsAddress := reserveDNSAddress(t)
	httpsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsAddress := httpsListener.Addr().String()
	httpsListener.Close()
	dir := t.TempDir()
	host := "127.0.0.1.home.arpa"
	args := []string{"--domain=home.arpa", "--ip=192.168.1.2", "--tls-mode=local",
		"--allowed-cidrs=127.0.0.1/32", "--data-dir=" + dir, "--dns-listen=" + dnsAddress,
		"--https-listen=" + httpsAddress, "--api-listen=", "--upstream-port=" + backendPort}
	issueArgs := append(append([]string{}, args...), "--issue="+host)
	if output, err := daemonCommand(t, issueArgs).CombinedOutput(); err != nil {
		t.Fatalf("preissue certificate: %v\n%s", err, output)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "ca", "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid local CA trust certificate")
	}
	var output processOutput
	cmd := daemonCommand(t, args)
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
	}()

	question := new(dns.Msg)
	question.SetQuestion(dns.Fqdn(host), dns.TypeA)
	for _, protocol := range []string{"udp", "tcp"} {
		client := dns.Client{Net: protocol, Timeout: 200 * time.Millisecond}
		deadline := time.Now().Add(10 * time.Second)
		for {
			response, _, queryErr := client.Exchange(question, dnsAddress)
			if queryErr == nil {
				if response.Rcode != dns.RcodeSuccess || !response.Authoritative || len(response.Answer) != 1 {
					t.Fatalf("%s DNS reply: %v", protocol, response)
				}
				answer, ok := response.Answer[0].(*dns.A)
				if !ok || answer.A.String() != "192.168.1.2" {
					t.Fatalf("DNS did not advertise the proxy: %v", response)
				}
				break
			}
			select {
			case processErr := <-done:
				stopped = true
				t.Fatalf("daemon exited before ready: %v\n%s", processErr, output.String())
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s DNS readiness: %v\n%s", protocol, queryErr, output.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, httpsAddress)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	var response *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err = client.Get("https://" + host + "/smoke?local=1")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("trusted TLS forwarding failed: %v\n%s", err, output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "backend "+host+" /smoke?local=1" {
		t.Fatalf("proxy reply: status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	before := backendCalls.Load()
	request, _ := http.NewRequest(http.MethodGet, "https://"+host+"/forbidden", nil)
	request.Host = "127.0.0.1.foreign.test"
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || backendCalls.Load() != before {
		t.Fatalf("out-of-zone Host reached backend: status=%d", response.StatusCode)
	}
	transport.CloseIdleConnections()
	if runtime.GOOS == "windows" {
		// Windows does not implement os.Process.Signal(SIGTERM).
		_ = cmd.Process.Kill()
		<-done
		stopped = true
		return
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("daemon did not stop cleanly: %v\n%s", err, output.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("daemon did not stop after SIGTERM\n%s", output.String())
	}
}

type processClusterCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	roots       *x509.CertPool
}

func newProcessClusterCA(t *testing.T) processClusterCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "process test cluster CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return processClusterCA{certificate: certificate, key: key, roots: roots}
}

func processClusterCredentials(t *testing.T, ca processClusterCA, ip, dir string) (cluster.Settings, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, IPAddresses: []net.IP{net.ParseIP(ip)},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	settings := cluster.Settings{Certificate: filepath.Join(dir, "cluster-node.crt"), PrivateKey: filepath.Join(dir, "cluster-node.key"), CACertificate: filepath.Join(dir, "cluster-ca.crt")}
	for path, data := range map[string][]byte{
		settings.Certificate: certPEM, settings.PrivateKey: keyPEM,
		settings.CACertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certificate.Raw}),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return settings, certificate
}

func writeProcessClusterConfig(t *testing.T, path string, settings cluster.Settings) {
	t.Helper()
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

type runningDaemon struct {
	cmd     *exec.Cmd
	output  processOutput
	done    chan error
	stopped bool
}

func startProcessDaemon(t *testing.T, args []string) *runningDaemon {
	t.Helper()
	process := &runningDaemon{cmd: daemonCommand(t, args), done: make(chan error, 1)}
	process.cmd.Stdout, process.cmd.Stderr = &process.output, &process.output
	if err := process.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.done <- process.cmd.Wait() }()
	t.Cleanup(func() {
		if !process.stopped {
			_ = process.cmd.Process.Kill()
			<-process.done
		}
	})
	return process
}

func processDNSQuery(t *testing.T, process *runningDaemon, address, protocol, name string, kind uint16) *dns.Msg {
	t.Helper()
	question := new(dns.Msg)
	question.SetQuestion(dns.Fqdn(name), kind)
	client := dns.Client{Net: protocol, Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, _, err := client.Exchange(question, address)
		if err == nil {
			return response
		}
		select {
		case processErr := <-process.done:
			process.stopped = true
			t.Fatalf("daemon exited before DNS query: %v\n%s", processErr, process.output.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s DNS query failed: %v\n%s", protocol, err, process.output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDaemonProcessThreeNodeCluster(t *testing.T) {
	ca := newProcessClusterCA(t)
	type node struct {
		settings                      cluster.Settings
		certificate                   tls.Certificate
		dir, dnsAddress, httpsAddress string
		process                       *runningDaemon
	}
	nodes := make([]node, 3)
	used := map[string]bool{}
	reserve := func() string {
		for {
			address := reserveDNSAddress(t)
			if !used[address] {
				used[address] = true
				return address
			}
		}
	}
	for i := range nodes {
		nodes[i].dir = t.TempDir()
		nodes[i].settings, nodes[i].certificate = processClusterCredentials(t, ca, "127.0.0.1", nodes[i].dir)
		nodes[i].dnsAddress, nodes[i].httpsAddress, nodes[i].settings.Listen = reserve(), reserve(), reserve()
	}
	for i := range nodes {
		for j := range nodes {
			if i != j {
				nodes[i].settings.Peers = append(nodes[i].settings.Peers, "https://"+nodes[j].settings.Listen)
			}
		}
		path := filepath.Join(nodes[i].dir, "cluster.json")
		writeProcessClusterConfig(t, path, nodes[i].settings)
		args := []string{"--domain=home.arpa", "--ip=127.0.0.1", fmt.Sprintf("--ns=ns%d", i+1),
			"--nameservers=ns3=127.0.0.1,ns1=127.0.0.1,ns2=127.0.0.1", "--tls-mode=local",
			"--allowed-cidrs=127.0.0.1/32", "--cluster-file=" + path, "--data-dir=" + filepath.Join(nodes[i].dir, "data"),
			"--dns-listen=" + nodes[i].dnsAddress, "--https-listen=" + nodes[i].httpsAddress, "--api-listen="}
		nodes[i].process = startProcessDaemon(t, args)
	}
	var authority []string
	for i := range nodes {
		for _, protocol := range []string{"udp", "tcp"} {
			var records []string
			for _, kind := range []uint16{dns.TypeNS, dns.TypeSOA} {
				response := processDNSQuery(t, nodes[i].process, nodes[i].dnsAddress, protocol, "home.arpa", kind)
				if !response.Authoritative || response.Rcode != dns.RcodeSuccess || response.Truncated {
					t.Fatalf("node %d %s authority: %v", i+1, protocol, response)
				}
				if (kind == dns.TypeNS && (len(response.Answer) != 3 || len(response.Extra) != 3)) || (kind == dns.TypeSOA && len(response.Answer) != 1) {
					t.Fatalf("node %d incomplete authority: %v", i+1, response)
				}
				for _, rr := range append(response.Answer, response.Extra...) {
					records = append(records, rr.String())
				}
			}
			if authority == nil {
				authority = records
			} else if !reflect.DeepEqual(authority, records) {
				t.Fatalf("node %d %s NS/glue/SOA differ: %v", i+1, protocol, records)
			}
			for _, name := range []string{"ns1.home.arpa", "ns2.home.arpa", "ns3.home.arpa", "127-0-0-1.home.arpa"} {
				response := processDNSQuery(t, nodes[i].process, nodes[i].dnsAddress, protocol, name, dns.TypeA)
				if !response.Authoritative || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
					t.Fatalf("node %d %s address: %v", i+1, protocol, response)
				}
				if rr, ok := response.Answer[0].(*dns.A); !ok || rr.A.String() != "127.0.0.1" {
					t.Fatalf("node %d wrong address: %v", i+1, response)
				}
			}
		}
	}
	// Drive the production publisher against three real daemon listeners. The
	// separate ACME tests verify that issuance invokes this publisher in order.
	if err := config.Load([]string{"--domain=home.arpa", "--ip=127.0.0.1", "--allowed-cidrs=127.0.0.1/32", "--tls-mode=local"}); err != nil {
		t.Fatal(err)
	}
	publisherSettings := nodes[0].settings
	publisherSettings.Listen = reserve()
	publisherSettings.Peers = nil
	for _, n := range nodes {
		publisherSettings.Peers = append(publisherSettings.Peers, "https://"+n.settings.Listen)
	}
	publisherPath := filepath.Join(t.TempDir(), "publisher.json")
	writeProcessClusterConfig(t, publisherPath, publisherSettings)
	publisher, err := cluster.Load(publisherPath)
	if err != nil {
		t.Fatal(err)
	}
	name := "_acme-challenge.127-0-0-1.home.arpa"
	tokens := []string{}
	cleanups := []func(context.Context) error{}
	for _, order := range []string{"first daemon order", "second daemon order"} {
		digest := sha256.Sum256([]byte(order))
		value := base64.RawURLEncoding.EncodeToString(digest[:])
		cleanup, err := publisher.Publish(context.Background(), name, value, 60)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, value)
		cleanups = append(cleanups, cleanup)
		t.Cleanup(func() {
			if err := cleanup(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	assertTXT := func(want []string) {
		t.Helper()
		expected := append([]string{}, want...)
		sort.Strings(expected)
		for i, n := range nodes {
			for _, protocol := range []string{"udp", "tcp"} {
				response := processDNSQuery(t, n.process, n.dnsAddress, protocol, name, dns.TypeTXT)
				values := []string{}
				for _, rr := range response.Answer {
					txt, ok := rr.(*dns.TXT)
					if !ok {
						t.Fatalf("non-TXT answer: %v", response)
					}
					values = append(values, strings.Join(txt.Txt, ""))
				}
				sort.Strings(values)
				if !response.Authoritative || response.Rcode != dns.RcodeSuccess || !reflect.DeepEqual(values, expected) {
					t.Fatalf("node %d %s TXT values %v, want %v: %v", i+1, protocol, values, expected, response)
				}
			}
		}
	}
	assertTXT(tokens)
	_, wrongPeer := processClusterCredentials(t, ca, "127.0.0.9", t.TempDir())
	_, foreignCert := processClusterCredentials(t, newProcessClusterCA(t), "127.0.0.1", t.TempDir())
	payload, _ := json.Marshal(map[string]any{"fqdn": name, "value": tokens[0], "ttl": 60})
	for _, certificates := range [][]tls.Certificate{nil, {wrongPeer}, {foreignCert}} {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, Certificates: certificates, MinVersion: tls.VersionTLS13}}
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		for i, n := range nodes {
			response, err := client.Post("https://"+n.settings.Listen+"/acme-challenge", "application/json", bytes.NewReader(payload))
			if err == nil {
				response.Body.Close()
				t.Fatalf("node %d accepted an unauthorized TLS client", i+1)
			}
		}
		transport.CloseIdleConnections()
	}
	assertTXT(tokens)
	if err := cleanups[0](context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTXT(tokens[1:])
	if err := cleanups[1](context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTXT(nil)
	for i := range nodes {
		p := nodes[i].process
		if runtime.GOOS == "windows" {
			_ = p.cmd.Process.Kill()
		} else if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
	}
	for i, n := range nodes {
		select {
		case err := <-n.process.done:
			n.process.stopped = true
			if err != nil && runtime.GOOS != "windows" {
				t.Fatalf("node %d did not stop cleanly: %v\n%s", i+1, err, n.process.output.String())
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("node %d did not stop\n%s", i+1, n.process.output.String())
		}
		for _, address := range []string{n.dnsAddress, n.httpsAddress, n.settings.Listen} {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("node %d left TCP %s bound: %v", i+1, address, err)
			}
			listener.Close()
		}
		packet, err := net.ListenPacket("udp", n.dnsAddress)
		if err != nil {
			t.Fatalf("node %d left UDP bound: %v", i+1, err)
		}
		packet.Close()
	}
}

func TestCheckConfigValidatesClusterBeforeSideEffects(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	dir := t.TempDir()
	settings, _ := processClusterCredentials(t, newProcessClusterCA(t), "127.0.0.1", dir)
	settings.Listen = occupied.Addr().String()
	settings.Peers = []string{"https://127.0.0.1:1"}
	validPath := filepath.Join(dir, "valid.json")
	writeProcessClusterConfig(t, validPath, settings)
	invalidPath := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte(`{"listen":`), 0600); err != nil {
		t.Fatal(err)
	}
	missingCredentials := settings
	missingCredentials.PrivateKey = filepath.Join(dir, "absent.key")
	missingKeyPath := filepath.Join(dir, "missing-key.json")
	writeProcessClusterConfig(t, missingKeyPath, missingCredentials)
	for _, tc := range []struct {
		name, path string
		valid      bool
	}{
		{"valid", validPath, true},
		{"missing file", filepath.Join(dir, "absent.json"), false},
		{"invalid JSON", invalidPath, false},
		{"missing credential", missingKeyPath, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "must-not-create")
			args := []string{"--check-config", "--domain=home.arpa", "--ip=127.0.0.1", "--tls-mode=local",
				"--data-dir=" + dataDir, "--cluster-file=" + tc.path, "--dns-listen=" + occupied.Addr().String(),
				"--https-listen=" + occupied.Addr().String(), "--api-listen="}
			output, err := daemonCommand(t, args).CombinedOutput()
			if tc.valid && (err != nil || !bytes.Contains(output, []byte("configuration is valid"))) {
				t.Fatalf("valid check tried to start services or failed: %v\n%s", err, output)
			}
			if !tc.valid && (err == nil || !bytes.Contains(output, []byte("cluster configuration"))) {
				t.Fatalf("invalid cluster check did not fail validation: %v\n%s", err, output)
			}
			if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
				t.Fatalf("check-config created its data directory: %v", err)
			}
		})
	}
}
