package txtstore

import (
	"fmt"
	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/utils"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var missCache = sync.Map{} // fqdn → time.Time

type entry struct {
	value     string
	expiresAt time.Time
}

var (
	store = make(map[string]entry)
	mu    sync.RWMutex
)

func Set(fqdn, value string, ttlSeconds int) {
	fqdn = normalizeFQDN(fqdn)
	log.Printf("[txtstore] Set(%s) = %s (ttl=%ds)", fqdn, value, ttlSeconds)
	mu.Lock()
	defer mu.Unlock()
	store[fqdn] = entry{
		value:     value,
		expiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	}
}

func Get(fqdn string) (string, bool) {
	val, ok := GetLocal(fqdn)
	if ok {
		return val, true
	}
	log.Printf("[txtstore] GetLocal(%s) → false (val=%s)", fqdn, val)

	if wasMissRecently(fqdn) {
		log.Printf("[txtstore] skipping lookup — recent miss for %s", fqdn)
		return "", false
	}

	selfIP := config.IP

	peers, err := utils.DiscoverPeers()
	if err != nil {
		markMiss(fqdn)
		return "", false
	}

	for _, peer := range peers {
		if peer == selfIP {
			continue
		}
		if val := queryPeerTXTOverHTTP(peer, fqdn); val != "" {
			Set(fqdn, val, 30)
			return val, true
		}
	}

	markMiss(fqdn)
	return "", false
}

func GetLocal(fqdn string) (string, bool) {
	fqdn = normalizeFQDN(fqdn)
	mu.RLock()
	defer mu.RUnlock()

	e, ok := store[fqdn]
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}

	return e.value, true
}

func Delete(fqdn string) {
	fqdn = normalizeFQDN(fqdn)
	log.Printf("[txtstore] Delete(%s)", fqdn)
	mu.Lock()
	defer mu.Unlock()
	delete(store, fqdn)
}

func queryPeerTXTOverHTTP(peer, fqdn string) string {
	url := fmt.Sprintf("http://%s/.dnsbox/txt/%s", peer, fqdn)

	client := &http.Client{
		Timeout: 2 * time.Second, // можно поднять до 3-5 сек при необходимости
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[query] TXT HTTP failed for %s via %s: %v", fqdn, peer, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[query] TXT HTTP response %d for %s via %s", resp.StatusCode, fqdn, peer)
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[query] TXT HTTP read failed for %s via %s: %v", fqdn, peer, err)
		return ""
	}

	return string(body)
}

func wasMissRecently(fqdn string) bool {
	if ts, ok := missCache.Load(fqdn); ok {
		return time.Since(ts.(time.Time)) < 30*time.Second
	}
	return false
}

func markMiss(fqdn string) {
	missCache.Store(fqdn, time.Now())
}

func normalizeFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}
