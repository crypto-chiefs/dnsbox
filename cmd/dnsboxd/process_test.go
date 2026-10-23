package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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
