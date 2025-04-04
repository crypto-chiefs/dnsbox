package txtstore

import (
	"context"
	"github.com/crypto-chiefs/dnsbox/internal/utils"
	"net"
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
	mu.RLock()
	e, ok := store[fqdn]
	mu.RUnlock()

	if ok && time.Now().Before(e.expiresAt) {
		return e.value, true
	}

	// Try discover peers via NS
	peers, err := utils.DiscoverPeers()
	if err != nil {
		return "", false
	}

	for _, peer := range peers {
		if val := queryPeerTXT(peer, fqdn); val != "" {
			Set(fqdn, val, 30)
			return val, true
		}
	}

	return "", false
}

func Delete(fqdn string) {
	mu.Lock()
	defer mu.Unlock()
	delete(store, fqdn)
}

func queryPeerTXT(peer, fqdn string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("udp", net.JoinHostPort(peer, "53"), time.Second)
		},
	}

	txts, err := r.LookupTXT(ctx, fqdn)
	if err != nil || len(txts) == 0 {
		return ""
	}
	return txts[0]
}
