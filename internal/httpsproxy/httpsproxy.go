package httpsproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/httpserver"
	"github.com/crypto-chiefs/dnsbox/internal/letsencrypt"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/crypto-chiefs/dnsbox/internal/resolver"
)

func requestHostname(authority string) (string, error) {
	if strings.Contains(authority, ":") {
		host, port, err := net.SplitHostPort(authority)
		if err != nil {
			return "", err
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", &net.AddrError{Err: "invalid port", Addr: authority}
		}
		authority = host
	}
	return config.ValidateHostname(authority)
}

func Handler() http.Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Traffic must go directly to the validated literal IP, never through an
	// HTTP_PROXY from the service environment or another DNS lookup.
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 4
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			host, _ := requestHostname(pr.In.Host) // validated by the outer handler
			ip, _ := resolver.ParseHost(host, config.Domain)
			target := &url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(config.UpstreamPort))}
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			// ReverseProxy removes untrusted forwarding headers before Rewrite.
			pr.Out.Header.Del("Forwarded")
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Warn("[httpsproxy] upstream request failed: %v", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, err := requestHostname(r.Host)
		if err != nil {
			http.Error(w, "invalid or disallowed target", http.StatusForbidden)
			return
		}
		if r.TLS == nil || !strings.EqualFold(strings.TrimSuffix(r.TLS.ServerName, "."), host) {
			http.Error(w, "Host must match TLS server name", http.StatusMisdirectedRequest)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr: config.HTTPSListen, Handler: Handler(),
		// TLS handshakes may include the initial ACME issuance; --issue permits
		// provisioning before serving traffic. HTTP headers still have a bound.
		ReadHeaderTimeout: config.ACMEDNSTimeout + 3*time.Minute,
		IdleTimeout:       60 * time.Second, MaxHeaderBytes: 32 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name, err := config.ValidateHostname(hello.ServerName)
				if err != nil {
					return nil, err
				}
				cert, err := letsencrypt.GetCertificate(hello.Context(), name)
				if err != nil {
					logger.Error("[httpsproxy] certificate for %s: %v", name, err)
					return nil, err
				}
				return &cert, nil
			},
		},
	}
	logger.Info("[httpsproxy] listening on %s", config.HTTPSListen)
	return httpserver.Serve(ctx, srv, true)
}

func Start() error { return Serve(context.Background()) }
