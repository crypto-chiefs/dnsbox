package utils

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	peersCache     []string
	cacheExpiresAt time.Time
	cacheMutex     sync.Mutex
)

func DiscoverPeers() ([]string, error) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// return cache, if valid
	if time.Now().Before(cacheExpiresAt) && len(peersCache) > 0 {
		return peersCache, nil
	}

	domain := os.Getenv("DNSBOX_DOMAIN")
	if domain == "" {
		return nil, fmt.Errorf("missing DNSBOX_DOMAIN")
	}

	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		return nil, err
	}

	var peers []string
	seen := make(map[string]bool)

	for _, ns := range nsRecords {
		host := strings.TrimSuffix(ns.Host, ".")
		ips, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if !seen[ip] {
				peers = append(peers, ip)
				seen[ip] = true
			}
		}
	}

	// update cache
	peersCache = peers
	cacheExpiresAt = time.Now().Add(5 * time.Minute)

	return peers, nil
}
