package txtstore

import (
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
	defer mu.RUnlock()

	e, ok := store[fqdn]
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.value, true
}
