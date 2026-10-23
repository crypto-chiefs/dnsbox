package httpsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/letsencrypt"
)

func setup(t *testing.T, port string) {
	t.Helper()
	if err := config.Load([]string{"--domain=home.arpa", "--ip=192.168.1.2", "--tls-mode=local",
		"--allowed-cidrs=127.0.0.1/32", "--data-dir=" + t.TempDir(), "--upstream-port=" + port}); err != nil {
		t.Fatal(err)
	}
}

func TestTargetAndSNIValidation(t *testing.T) {
	setup(t, "80")
	handler := Handler()
	for _, tt := range []struct {
		host, sni string
		code      int
	}{
		{"127.0.0.1.home.arpa", "8.8.8.8.home.arpa", 421},
		{"127.0.0.1.evil.test", "127.0.0.1.evil.test", 403},
		{"169.254.169.254.home.arpa", "169.254.169.254.home.arpa", 403},
		{"127.0.0.1.home.arpa:invalid", "127.0.0.1.home.arpa", 403},
		{"127.0.0.1.home.arpa", "", 421},
	} {
		r := httptest.NewRequest("GET", "https://example.test/", nil)
		r.Host = tt.host
		r.TLS = &tls.ConnectionState{ServerName: tt.sni}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tt.code {
			t.Errorf("%s/%s: %d", tt.host, tt.sni, w.Code)
		}
	}
}

func TestLocalTLSProxyAndWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			_ = rw.Flush()
			data := make([]byte, 4)
			if _, err := io.ReadFull(rw, data); err == nil {
				_, _ = rw.Write(data)
				_ = rw.Flush()
			}
			return
		}
		if r.Header.Get("Forwarded") != "" || strings.Contains(r.Header.Get("X-Forwarded-For"), "attacker") {
			t.Error("forwarding headers trusted")
		}
		if r.Header.Get("X-Forwarded-Proto") != "https" || r.URL.RequestURI() != "/hello?x=1" {
			t.Error("request not preserved", r.URL, r.Header)
		}
		fmt.Fprint(w, "backend:"+r.Host)
	}))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	setup(t, port)
	host := "127.0.0.1.home.arpa"
	certificate, err := letsencrypt.GetCertificate(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join(config.DataDir, "ca", "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("bad root")
	}
	server := httptest.NewUnstartedServer(Handler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	address := server.Listener.Addr().String()
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "https://"+host+"/hello?x=1", nil)
	req.Header.Set("X-Forwarded-For", "attacker")
	req.Header.Set("Forwarded", "for=attacker")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "backend:"+host {
		t.Fatal(response.Status, string(body))
	}
	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n", host)
	reader := bufio.NewReader(conn)
	response, err = http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatal("upgrade", response.Status)
	}
	_, _ = conn.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "ping" {
		t.Fatal("upgrade tunnel", string(echo), err)
	}
}
