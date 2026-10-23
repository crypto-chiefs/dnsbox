package txtstore

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const MaxEntries = 4096
const MaxTTL = 24 * 60 * 60
const MaxValueBytes = 4096

type entry struct {
	value     string
	expiresAt time.Time
}

var (
	store = make(map[string]entry)
	mu    sync.RWMutex
)

// Put stores a short-lived TXT record. Expired records are reclaimed on writes
// and reads; there is no network access or unbounded negative lookup cache.
func Put(fqdn, value string, ttlSeconds int) error {
	fqdn = normalizeFQDN(fqdn)
	if _, ok := dns.IsDomainName(fqdn); !ok || fqdn == "." || len(fqdn) > 254 {
		return fmt.Errorf("invalid TXT record name")
	}
	if value == "" || len(value) > MaxValueBytes || ttlSeconds <= 0 || ttlSeconds > MaxTTL {
		return fmt.Errorf("invalid TXT value or lifetime")
	}
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	for name, e := range store {
		if !now.Before(e.expiresAt) {
			delete(store, name)
		}
	}
	if _, exists := store[fqdn]; !exists && len(store) >= MaxEntries {
		return fmt.Errorf("TXT record store is full")
	}
	store[fqdn] = entry{value: value, expiresAt: now.Add(time.Duration(ttlSeconds) * time.Second)}
	return nil
}

func Set(fqdn, value string, ttlSeconds int) { _ = Put(fqdn, value, ttlSeconds) }
func Get(fqdn string) (string, bool)         { return GetLocal(fqdn) }
func GetLocal(fqdn string) (string, bool) {
	fqdn = normalizeFQDN(fqdn)
	mu.Lock()
	defer mu.Unlock()
	e, ok := store[fqdn]
	if !ok {
		return "", false
	}
	if !time.Now().Before(e.expiresAt) {
		delete(store, fqdn)
		return "", false
	}
	return e.value, true
}
func Delete(fqdn string) {
	mu.Lock()
	defer mu.Unlock()
	delete(store, normalizeFQDN(fqdn))
}
func normalizeFQDN(fqdn string) string { return dns.Fqdn(strings.ToLower(strings.TrimSpace(fqdn))) }
