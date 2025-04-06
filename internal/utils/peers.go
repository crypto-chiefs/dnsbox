package utils

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/rand"
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

var rootServers = []string{
	"a.root-servers.net.",
	"b.root-servers.net.",
	"c.root-servers.net.",
	"d.root-servers.net.",
	"e.root-servers.net.",
	"f.root-servers.net.",
	"g.root-servers.net.",
	"h.root-servers.net.",
	"i.root-servers.net.",
	"j.root-servers.net.",
	"k.root-servers.net.",
	"l.root-servers.net.",
	"m.root-servers.net.",
}

var allowedPeerIPs sync.Map

func pickRootServerIP() (string, error) {
	rand.Seed(time.Now().UnixNano())
	for _, name := range shuffled(rootServers) {
		ips, err := net.LookupIP(name)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			addr := ip.String()
			if ip.To4() == nil {
				// IPv6
				addr = fmt.Sprintf("[%s]:53", addr)
			} else {
				// IPv4
				addr = addr + ":53"
			}
			return addr, nil
		}
	}
	return "", fmt.Errorf("failed to resolve any root server")
}

func shuffled(list []string) []string {
	rand.Seed(time.Now().UnixNano())
	shuffled := append([]string(nil), list...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled
}

func DiscoverPeers() ([]string, error) {
	log.Println("[discover] DiscoverPeers() called")

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if time.Now().Before(cacheExpiresAt) && len(peersCache) > 0 {
		log.Printf("[discover] Using cached peers: %v (expires at %s)", peersCache, cacheExpiresAt.Format(time.RFC3339))
		return peersCache, nil
	}

	domain := os.Getenv("DNSBOX_DOMAIN")
	if domain == "" {
		return nil, fmt.Errorf("missing DNSBOX_DOMAIN env variable")
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}
	tld := parts[len(parts)-1]

	rootIP, err := pickRootServerIP()
	if err != nil {
		return nil, fmt.Errorf("unable to pick root server: %v", err)
	}

	c := new(dns.Client)

	m1 := new(dns.Msg)
	m1.SetQuestion(dns.Fqdn(tld), dns.TypeNS)
	resp1, _, err := c.Exchange(m1, rootIP)
	if err != nil {
		return nil, fmt.Errorf("root query failed: %v", err)
	}

	var tldServers []string
	for _, rr := range resp1.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			tldServers = append(tldServers, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	if len(tldServers) == 0 {
		return nil, fmt.Errorf("no NS found for TLD .%s", tld)
	}

	var tldIP string
	for _, tldHost := range shuffled(tldServers) {
		ips, err := net.LookupHost(tldHost)
		if err == nil && len(ips) > 0 {
			ip := net.ParseIP(ips[0])
			if ip == nil {
				return nil, fmt.Errorf("invalid IP for TLD NS: %s", ips[0])
			}
			if ip.To4() == nil {
				tldIP = fmt.Sprintf("[%s]:53", ip.String())
			} else {
				tldIP = ip.String() + ":53"
			}
			break
		}
	}
	if tldIP == "" {
		return nil, fmt.Errorf("could not resolve TLD NS IP")
	}

	m2 := new(dns.Msg)
	m2.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	resp2, _, err := c.Exchange(m2, tldIP)
	if err != nil {
		return nil, fmt.Errorf("TLD-level query failed: %v", err)
	}

	ipMap := make(map[string]bool)
	for _, rr := range resp2.Extra {
		if a, ok := rr.(*dns.A); ok {
			ipMap[a.A.String()] = true
		}
	}

	if len(ipMap) == 0 {
		for _, rr := range resp2.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				host := strings.TrimSuffix(ns.Ns, ".")
				ips, err := net.LookupHost(host)
				if err == nil {
					for _, ip := range ips {
						ipMap[ip] = true
					}
				}
			}
		}
	}

	var peers []string
	for ip := range ipMap {
		peers = append(peers, ip)
	}

	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers resolved from NS")
	}

	peersCache = peers
	cacheExpiresAt = time.Now().Add(5 * time.Minute)
	log.Printf("[discover] Final peers: %v", peers)
	return peers, nil
}

func IsAllowedPeer(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	log.Printf("[txt-http] checking peer IP: %s", host)

	if _, ok := allowedPeerIPs.Load(host); ok {
		log.Printf("[txt-http] peer %s is already allowed", host)
		return true
	}

	log.Printf("[txt-http] peer %s not in allowed cache, refreshing peers", host)

	peers, err := DiscoverPeers()
	if err == nil {
		for _, p := range peers {
			log.Printf("[txt-http] caching peer %s", p)
			allowedPeerIPs.Store(p, true)
		}
	}

	allowedPeerIPs.Store("127.0.0.1", true)
	allowedPeerIPs.Store("::1", true)

	_, ok := allowedPeerIPs.Load(host)
	if ok {
		log.Printf("[txt-http] peer %s is now allowed", host)
	} else {
		log.Printf("[txt-http] peer %s is still not allowed", host)
	}

	return ok
}
