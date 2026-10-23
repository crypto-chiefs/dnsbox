package letsencrypt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
)

type acmeFixture struct {
	t                                          *testing.T
	server                                     *httptest.Server
	mu                                         sync.Mutex
	root                                       *x509.Certificate
	key                                        *ecdsa.PrivateKey
	nonce, orders, accepts                     int
	domain                                     string
	alreadyValid, authorized, ready, finalized bool
	certPEM                                    []byte
	accountJWK                                 json.RawMessage
}

func newACMEFixture(t *testing.T, alreadyValid bool) *acmeFixture {
	t.Helper()
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACME Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &acmeFixture{t: t, root: root, key: key, alreadyValid: alreadyValid}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	oldClient, oldCheck := acmeHTTPClient, checkPropagation
	acmeHTTPClient = f.server.Client()
	checkPropagation = func(ctx context.Context, name, value string) error {
		found := false
		for _, got := range txtstore.GetAll(name) {
			if got == value {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("TXT was not installed before propagation check")
		}
		return ctx.Err()
	}
	t.Cleanup(func() { acmeHTTPClient, checkPropagation = oldClient, oldCheck })
	config.ACMEDirectory = f.server.URL + "/directory"
	return f
}

func (f *acmeFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", f.nonce))
	w.Header().Set("Content-Type", "application/json")
	writeJSON := func(status int, v any) {
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(v); err != nil {
			f.t.Error(err)
		}
	}
	var request struct{ Protected, Payload string }
	var payload []byte
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Error(err)
			http.Error(w, "bad JWS", 400)
			return
		}
		var err error
		payload, err = base64.RawURLEncoding.DecodeString(request.Payload)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "bad payload", 400)
			return
		}
	}
	switch r.URL.Path {
	case "/directory":
		writeJSON(200, map[string]any{"newNonce": f.server.URL + "/nonce", "newAccount": f.server.URL + "/account", "newOrder": f.server.URL + "/new-order"})
	case "/nonce":
		w.WriteHeader(200)
	case "/account":
		protected, err := base64.RawURLEncoding.DecodeString(request.Protected)
		if err != nil {
			f.t.Error(err)
		}
		var header struct {
			JWK json.RawMessage `json:"jwk"`
		}
		if err := json.Unmarshal(protected, &header); err != nil {
			f.t.Error(err)
		}
		status := 201
		if f.accountJWK != nil {
			status = 200
			if !bytes.Equal(f.accountJWK, header.JWK) {
				f.t.Error("ACME account key changed across requests")
			}
		} else {
			f.accountJWK = header.JWK
		}
		w.Header().Set("Location", f.server.URL+"/account/1")
		writeJSON(status, map[string]any{"status": "valid"})
	case "/new-order":
		var body struct {
			Identifiers []struct{ Type, Value string }
		}
		if err := json.Unmarshal(payload, &body); err != nil || len(body.Identifiers) != 1 {
			f.t.Error("invalid identifiers")
			http.Error(w, "invalid order", 400)
			return
		}
		f.domain = body.Identifiers[0].Value
		f.orders++
		f.authorized = f.alreadyValid
		f.ready = false
		f.finalized = false
		w.Header().Set("Location", f.server.URL+"/order/1")
		writeJSON(201, f.order("pending"))
	case "/authorization/1":
		status := "pending"
		if f.authorized {
			status = "valid"
		}
		writeJSON(200, map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": f.domain}, "challenges": []any{map[string]string{"type": "dns-01", "url": f.server.URL + "/challenge/1", "status": "pending", "token": "fixture-token"}}})
	case "/challenge/1":
		if value, ok := txtstore.GetLocal("_acme-challenge." + f.domain); !ok || value == "" {
			f.t.Error("TXT missing when challenge accepted")
		}
		f.accepts++
		f.authorized = true
		writeJSON(200, map[string]string{"type": "dns-01", "url": f.server.URL + "/challenge/1", "status": "valid", "token": "fixture-token"})
	case "/order/1":
		status := "pending"
		if f.authorized {
			status = "ready"
			f.ready = true
		}
		if f.finalized {
			status = "valid"
		}
		writeJSON(200, f.order(status))
	case "/finalize/1":
		if !f.ready {
			f.t.Error("finalized before waiting for ready order")
			http.Error(w, "not ready", 400)
			return
		}
		if !f.alreadyValid {
			if _, ok := txtstore.GetLocal("_acme-challenge." + f.domain); !ok {
				f.t.Error("TXT removed before finalization")
			}
		}
		var body struct{ CSR string }
		if err := json.Unmarshal(payload, &body); err != nil {
			f.t.Error(err)
		}
		der, err := base64.RawURLEncoding.DecodeString(body.CSR)
		if err != nil {
			f.t.Error(err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "bad CSR", 400)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			f.t.Error(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(f.orders + 1)), DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err = x509.CreateCertificate(rand.Reader, leaf, f.root, csr.PublicKey, f.key)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "sign error", 500)
			return
		}
		f.certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})...)
		f.finalized = true
		writeJSON(200, f.order("valid"))
	case "/certificate/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, err := w.Write(f.certPEM)
		if err != nil {
			f.t.Error(err)
		}
	default:
		f.t.Errorf("unexpected ACME request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *acmeFixture) order(status string) map[string]any {
	return map[string]any{"status": status, "identifiers": []any{map[string]string{"type": "dns", "value": f.domain}}, "authorizations": []string{f.server.URL + "/authorization/1"}, "finalize": f.server.URL + "/finalize/1", "certificate": f.server.URL + "/certificate/1"}
}

func TestACMEProtocolFullChainAccountReuseAndAuthorization(t *testing.T) {
	for _, alreadyValid := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing-authorization-%t", alreadyValid), func(t *testing.T) {
			configureTest(t, "acme")
			fixture := newACMEFixture(t, alreadyValid)
			for _, domain := range []string{"192-168-1-10.example.test", "192-168-1-11.example.test"} {
				cert, err := GetCertificate(context.Background(), domain)
				if err != nil {
					t.Fatal(err)
				}
				if len(cert.Certificate) != 2 {
					t.Fatalf("chain length = %d, want 2", len(cert.Certificate))
				}
				roots := x509.NewCertPool()
				roots.AddCert(fixture.root)
				if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: domain}); err != nil {
					t.Fatal(err)
				}
				if _, ok := txtstore.GetLocal("_acme-challenge." + domain); ok {
					t.Fatal("TXT not cleaned up after order completion")
				}
				if _, err := GetCertificate(context.Background(), strings.ToUpper(domain)+"."); err != nil {
					t.Fatal(err)
				}
			}
			fixture.mu.Lock()
			orders, accepts := fixture.orders, fixture.accepts
			fixture.mu.Unlock()
			if orders != 2 {
				t.Fatalf("made %d orders, want 2", orders)
			}
			if alreadyValid && accepts != 0 {
				t.Fatal("revalidated an already-valid authorization")
			}
			if !alreadyValid && accepts != 2 {
				t.Fatal("did not validate both authorizations")
			}
			keys, err := filepath.Glob(filepath.Join(config.DataDir, "acme", "*.key"))
			if err != nil || len(keys) != 1 {
				t.Fatalf("expected one persistent account key, got %v (%v)", keys, err)
			}
			if data, err := os.ReadFile(keys[0]); err != nil || !bytes.Contains(data, []byte("PRIVATE KEY")) {
				t.Fatal("account key not persisted")
			}
			config.ACMEDirectory = "https://different-ca.example/directory"
			if HasCertificate("192-168-1-10.example.test") {
				t.Fatal("certificate reused after changing ACME CA")
			}
		})
	}
}

func TestACMEPropagationFailureCleansTXTAndLimitsRetry(t *testing.T) {
	configureTest(t, "acme")
	fixture := newACMEFixture(t, false)
	checkPropagation = func(context.Context, string, string) error { return errors.New("wrong delegation") }
	const domain = "192-168-1-10.example.test"
	for range 2 {
		if _, err := GetCertificate(context.Background(), domain); err == nil || !strings.Contains(err.Error(), "wrong delegation") {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := txtstore.GetLocal("_acme-challenge." + domain); ok {
			t.Fatal("failed challenge left TXT behind")
		}
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.orders != 1 || fixture.accepts != 0 {
		t.Fatalf("got orders=%d, accepts=%d; expected one order, no validation attempts", fixture.orders, fixture.accepts)
	}
}

func TestLegacyFullChainMigration(t *testing.T) {
	configureTest(t, "acme")
	newACMEFixture(t, false)
	const domain = "192-168-1-10.example.test"
	cert, err := IssueCertificateContext(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := encodeCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.DataDir, "certs", domain+".crt"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cacheDirectory(), domain+".pem")); err != nil {
		t.Fatal(err)
	}
	config.ACMEDirectory = "" // Legacy releases only used production.
	if err := migrateLegacyCertificates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cacheDirectory(), domain+".pem")); err != nil {
		t.Fatalf("legacy certificate not adopted by renewal scheduler: %v", err)
	}
	loaded, err := LoadCertificate(domain)
	if err != nil || !bytes.Equal(loaded.Certificate[0], cert.Certificate[0]) {
		t.Fatalf("migration altered certificate: %v", err)
	}
}

func TestDirectorySwitchDoesNotAdoptStagingExports(t *testing.T) {
	configureTest(t, "acme")
	newACMEFixture(t, false)
	const domain = "192-168-1-10.example.test"
	if _, err := IssueCertificateContext(context.Background(), domain); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cacheDirectory(), domain+".pem")); err != nil {
		t.Fatal(err)
	}
	config.ACMEDirectory = ""
	if HasCertificate(domain) {
		t.Fatal("staging exports adopted by production after bundle loss")
	}
}

func TestACMEPublisherOrdersReplicationBeforeValidationAndCleansExactValues(t *testing.T) {
	for _, failPropagation := range []bool{false, true} {
		t.Run(fmt.Sprintf("propagation-fails-%t", failPropagation), func(t *testing.T) {
			configureTest(t, "acme")
			fixture := newACMEFixture(t, false)
			oldPublisher := challengePublisher
			t.Cleanup(func() { challengePublisher = oldPublisher })
			replicas := []*txtstore.Store{txtstore.New(), txtstore.New()}
			const domain = "192-168-1-10.example.test"
			const name = "_acme-challenge." + domain
			const unrelated = "another-active-order"
			if err := txtstore.Add(name, unrelated, 120); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { txtstore.DeleteValue(name, unrelated) })
			for _, replica := range replicas {
				if err := replica.Add(name, unrelated, 120); err != nil {
					t.Fatal(err)
				}
			}
			cleanupCalled := false
			SetChallengePublisher(func(ctx context.Context, name, value string, ttl int) (func(context.Context) error, error) {
				localCleanup, err := publishLocally(ctx, name, value, ttl)
				if err != nil {
					return nil, err
				}
				for _, replica := range replicas {
					if err := replica.Add(name, value, ttl); err != nil {
						return nil, err
					}
				}
				return func(cleanupCtx context.Context) error {
					if cleanupCtx.Err() != nil {
						t.Error("cleanup received canceled context")
					}
					cleanupCalled = true
					for _, replica := range replicas {
						replica.DeleteValue(name, value)
					}
					return localCleanup(cleanupCtx)
				}, nil
			})
			checkPropagation = func(ctx context.Context, name, value string) error {
				for i, replica := range replicas {
					found := false
					for _, got := range replica.GetAll(name) {
						if got == value {
							found = true
						}
					}
					if !found {
						t.Errorf("ACME validation reached before replica %d stored challenge", i)
					}
				}
				if failPropagation {
					return errors.New("propagation failed")
				}
				return nil
			}
			_, err := IssueCertificateContext(context.Background(), domain)
			if (err != nil) != failPropagation {
				t.Fatalf("unexpected issuance result: %v", err)
			}
			if !cleanupCalled {
				t.Fatal("ACME did not clean the published challenge")
			}
			for i, replica := range replicas {
				if got := replica.GetAll(name); len(got) != 1 || got[0] != unrelated {
					t.Fatalf("replica %d lost independent order: %v", i, got)
				}
			}
			if got := txtstore.GetAll(name); len(got) != 1 || got[0] != unrelated {
				t.Fatalf("local cleanup lost independent order: %v", got)
			}
			fixture.mu.Lock()
			accepts := fixture.accepts
			fixture.mu.Unlock()
			if failPropagation && accepts != 0 {
				t.Fatal("ACME accepted challenge after failed propagation")
			}
		})
	}
}

func TestACMEPublisherFailureStopsBeforeValidation(t *testing.T) {
	configureTest(t, "acme")
	fixture := newACMEFixture(t, false)
	oldPublisher := challengePublisher
	t.Cleanup(func() { challengePublisher = oldPublisher })
	SetChallengePublisher(func(context.Context, string, string, int) (func(context.Context) error, error) {
		return nil, errors.New("peer unavailable")
	})
	checkPropagation = func(context.Context, string, string) error {
		t.Error("checked propagation after publication failure")
		return nil
	}
	if _, err := IssueCertificateContext(context.Background(), "192-168-1-10.example.test"); err == nil || !strings.Contains(err.Error(), "peer unavailable") {
		t.Fatalf("unexpected result: %v", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.accepts != 0 {
		t.Fatal("accepted challenge despite failed peer publication")
	}
}
