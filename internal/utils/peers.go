package utils

import (
	"fmt"
	"log"
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

	log.Println("[discover] DiscoverPeers() called")

	// Return cache if still valid
	if time.Now().Before(cacheExpiresAt) && len(peersCache) > 0 {
		log.Printf("[discover] Using cached peers: %v (expires at %s)", peersCache, cacheExpiresAt.Format(time.RFC3339))
		return peersCache, nil
	}

	domain := os.Getenv("DNSBOX_DOMAIN")
	if domain == "" {
		log.Println("[discover] Missing DNSBOX_DOMAIN env variable")
		return nil, fmt.Errorf("missing DNSBOX_DOMAIN")
	}

	log.Printf("[discover] Resolving NS records for domain: %s", domain)

	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		log.Printf("[discover] Error resolving NS records for %s: %v", domain, err)
		return nil, err
	}

	var peers []string
	seen := make(map[string]bool)

	for _, ns := range nsRecords {
		host := strings.TrimSuffix(ns.Host, ".")
		log.Printf("[discover] Found NS: %s", host)

		ips, err := net.LookupHost(host)
		if err != nil {
			log.Printf("[discover] Failed to resolve IPs for %s: %v", host, err)
			continue
		}

		for _, ip := range ips {
			if net.ParseIP(ip) == nil {
				log.Printf("[discover] Skipping invalid resolved IP for %s: %q", host, ip)
				continue
			}
			if !seen[ip] {
				log.Printf("[discover] Resolved %s → %s", host, ip)
				peers = append(peers, ip)
				seen[ip] = true
			}
		}
	}

	if len(peers) == 0 {
		log.Println("[discover] No valid peers discovered — returning empty list")
	} else {
		log.Printf("[discover] Final peer list: %v", peers)
	}

	// Update cache
	peersCache = peers
	cacheExpiresAt = time.Now().Add(5 * time.Minute)
	log.Printf("[discover] Cache updated. Expires at %s", cacheExpiresAt.Format(time.RFC3339))

	return peers, nil
}
