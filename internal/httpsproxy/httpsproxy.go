package httpsproxy

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/certshare"
	"github.com/crypto-chiefs/dnsbox/internal/letsencrypt"
	"github.com/crypto-chiefs/dnsbox/internal/utils"
)

var (
	certMu  sync.Mutex
	certMap = make(map[string][]byte)
)

func StoreEncryptedCert(domain string, data []byte) {
	certMu.Lock()
	defer certMu.Unlock()
	certMap[domain] = data
}

func extractIPFromDomain(host string) string {
	host = strings.Split(host, ":")[0]
	parts := strings.Split(host, ".")
	if len(parts) < 5 {
		return ""
	}
	return strings.ReplaceAll(parts[0], "-", ".")
}

func Start() error {
	server := &http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIPFromDomain(r.Host)
			if net.ParseIP(ip) == nil {
				http.Error(w, "Invalid target", http.StatusBadRequest)
				return
			}
			proxy := httputil.NewSingleHostReverseProxy(&url.URL{
				Scheme: "http",
				Host:   ip,
			})
			proxy.ServeHTTP(w, r)
		}),
		TLSConfig: &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				domain := chi.ServerName
				cert, err := fetchCertificate(domain)
				if err != nil {
					log.Printf("[httpsproxy] failed to fetch cert for %s: %v", domain, err)
					return nil, err
				}
				return &cert, nil
			},
			MinVersion: tls.VersionTLS12,
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	fmt.Println("[httpsproxy] listening on :443")
	return server.ListenAndServeTLS("", "")
}

func fetchCertificate(domain string) (tls.Certificate, error) {
	if letsencrypt.HasCertificate(domain) {
		return letsencrypt.LoadCertificate(domain)
	}

	priv, pub, err := certshare.GenerateEphemeralKeyPair()
	if err != nil {
		return tls.Certificate{}, err
	}

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	callback := "http://" + getLocalIP() + ":80/.dnsbox/receive-cert"

	peers, err := utils.DiscoverPeers()
	if err != nil {
		return tls.Certificate{}, err
	}

	req := certshare.AskRequest{
		Domain:       domain,
		FromIP:       getLocalIP(),
		EphemeralPub: pubB64,
		Callback:     callback,
	}

	hasCertChan := make(chan bool, len(peers))
	for _, peer := range peers {
		peer := peer
		go func() {
			ok, err := certshare.SendAskRequest(peer, req)
			if err == nil && ok {
				log.Printf("[httpsproxy] peer %s has cert", peer)
				hasCertChan <- true
			} else {
				hasCertChan <- false
			}
		}()
	}

	anyHasCert := false
	for i := 0; i < len(peers); i++ {
		if <-hasCertChan {
			anyHasCert = true
		}
	}

	if anyHasCert {
		cert, err := waitForCertificate(domain, priv, 5*time.Second)
		if err == nil {
			return cert, nil
		}
		log.Printf("[httpsproxy] peer had cert but delivery failed: %v", err)
	} else {
		log.Printf("[httpsproxy] no peer has cert, generating via Let's Encrypt")
	}

	return letsencrypt.IssueCertificate(domain)
}

func getLocalIP() string {
	if ip := os.Getenv("DNSBOX_IP"); ip != "" {
		return ip
	}
	return "127.0.0.1"
}

func waitForCertificate(domain string, priv []byte, timeout time.Duration) (tls.Certificate, error) {
	start := time.Now()
	for time.Since(start) < timeout {
		certMu.Lock()
		data, ok := certMap[domain]
		if ok {
			delete(certMap, domain)
			certMu.Unlock()

			decoded := make(map[string]string)
			if err := json.Unmarshal(data, &decoded); err != nil {
				return tls.Certificate{}, err
			}
			cipher, _ := base64.StdEncoding.DecodeString(decoded["encrypted"])
			nonce, _ := base64.StdEncoding.DecodeString(decoded["nonce"])
			cert, err := certshare.DecryptCertWithSharedKey(cipher, nonce, priv)
			if err != nil {
				return tls.Certificate{}, err
			}
			return cert, nil
		}
		certMu.Unlock()
		time.Sleep(250 * time.Millisecond)
	}
	return tls.Certificate{}, fmt.Errorf("timeout waiting for cert")
}
