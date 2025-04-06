package txtstore

import (
	"fmt"
	"github.com/crypto-chiefs/dnsbox/internal/utils"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

type entry struct {
	value     string
	expiresAt time.Time
}

var (
	store = make(map[string]entry)
	mu    sync.RWMutex
)

func Set(fqdn, value string, ttlSeconds int) {
	mu.Lock()
	defer mu.Unlock()
	store[fqdn] = entry{
		value:     value,
		expiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	}
}

func Get(fqdn string) (string, bool) {
	if val, ok := GetLocal(fqdn); ok {
		return val, true
	}

	peers, err := utils.DiscoverPeers()
	if err != nil {
		return "", false
	}

	for _, peer := range peers {
		if val := queryPeerTXTOverHTTP(peer, fqdn); val != "" {
			Set(fqdn, val, 30)
			return val, true
		}
	}

	return "", false
}

func GetLocal(fqdn string) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()

	e, ok := store[fqdn]
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}

	return e.value, true
}

func Delete(fqdn string) {
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
