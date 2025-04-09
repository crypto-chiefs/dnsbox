package utils

import (
	"fmt"
	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type Peer struct {
	Name string // FQDN ns1.dnsbox.io.
	IP   string // IPv4 or IPv6
}

var (
	peersCache     []Peer
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

func DiscoverPeers() ([]Peer, error) {
	logger.Debug("[discover] DiscoverPeers() called")

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if time.Now().Before(cacheExpiresAt) && len(peersCache) > 0 {
		logger.Debug("[discover] Using cached peers: %v (expires at %s)", peersCache, cacheExpiresAt.Format(time.RFC3339))
		return peersCache, nil
	}

	domain := config.Domain
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

	var peers []Peer
	peerSet := make(map[string]struct{})

	for _, rr := range resp2.Extra {
		if a, ok := rr.(*dns.A); ok {
			name := strings.TrimSuffix(a.Hdr.Name, ".")
			if _, exists := peerSet[name]; !exists {
				peers = append(peers, Peer{
					Name: name,
					IP:   a.A.String(),
				})
				peerSet[name] = struct{}{}
			}
		}
	}

	if len(peers) == 0 {
		for _, rr := range resp2.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				name := strings.TrimSuffix(ns.Ns, ".")
				if _, exists := peerSet[name]; exists {
					continue
				}
				ips, err := net.LookupHost(name)
				if err == nil {
					for _, ip := range ips {
						peers = append(peers, Peer{
							Name: name,
							IP:   ip,
						})
						peerSet[name] = struct{}{}
					}
				}
			}
		}
	}

	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers resolved from NS")
	}

	peersCache = peers
	cacheExpiresAt = time.Now().Add(5 * time.Minute)
	logger.Info("[discover] Final peers: %v", peers)
	return peers, nil
}
