package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
)

func TestChallengeAPIAuthorizationAndValidation(t *testing.T) {
	if err := config.Load([]string{"--domain=example.test", "--ip=192.168.1.2", "--api-token=test-token"}); err != nil {
		t.Fatal(err)
	}
	handler := Handler()
	tests := []struct {
		method, path, token, body string
		status                    int
	}{
		{"GET", "/healthz", "", "", 200},
		{"POST", "/.dnsbox/ask-cert", "", "{}", 410},
		{"POST", "/.dnsbox/receive-cert", "", "{}", 410},
		{"POST", "/acme-challenge", "", `{"fqdn":"_acme-challenge.8.8.8.8.example.test","value":"test","ttl":60}`, 401},
		{"GET", "/acme-challenge", "test-token", "", 405},
		{"POST", "/acme-challenge", "test-token", `{"fqdn":"evil.test","value":"test","ttl":60}`, 400},
		{"POST", "/acme-challenge", "test-token", `{"fqdn":"_acme-challenge.127.0.0.1.example.test","value":"test","ttl":60}`, 400},
		{"POST", "/acme-challenge", "test-token", `{"fqdn":"_acme-challenge.8.8.8.8.example.test","value":"test","ttl":999999999}`, 400},
		{"POST", "/acme-challenge", "test-token", `{"fqdn":"_acme-challenge.8.8.8.8.example.test","value":"test","ttl":60}{}`, 400},
		{"POST", "/acme-challenge", "test-token", strings.Repeat("x", 9000), 400},
		{"POST", "/acme-challenge", "test-token", `{"fqdn":"_ACME-challenge.8.8.8.8.EXAMPLE.TEST.","value":"test","ttl":60}`, 204},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
		if tt.token != "" {
			r.Header.Set("Authorization", "Bearer "+tt.token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Errorf("%s %s => %d want %d: %s", tt.method, tt.path, w.Code, tt.status, w.Body)
		}
	}
	if value, ok := txtstore.Get("_acme-challenge.8.8.8.8.example.test."); !ok || value != "test" {
		t.Fatal("TXT not stored")
	}
	r := httptest.NewRequest(http.MethodDelete, "/acme-challenge", strings.NewReader(`{"fqdn":"_acme-challenge.8.8.8.8.example.test"}`))
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	if _, ok := txtstore.Get("_acme-challenge.8.8.8.8.example.test."); ok {
		t.Fatal("TXT not deleted")
	}
	config.APIToken = ""
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unconfigured API accepts writes")
	}
}
