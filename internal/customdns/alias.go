package customdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/miekg/dns"
)

const (
	aliasLookupTimeout = 5 * time.Second
	aliasRefreshPeriod = time.Minute
	aliasMaxAge        = time.Hour
	aliasTTL           = uint32(60)
)

type aliasEntry struct {
	target      string
	addresses   []dns.RR
	refreshedAt time.Time
}

// Test seams keep cache and failure behavior deterministic without public DNS.
var aliasLookupIP = net.DefaultResolver.LookupIPAddr
var aliasNow = time.Now

func conflictsWithAlias(kind uint16) bool {
	return kind == dns.TypeA || kind == dns.TypeAAAA || kind == dns.TypeCNAME
}

func validateAliasTarget(target, zone string) (string, error) {
	target = strings.TrimSuffix(strings.ToLower(target), ".")
	if target == "" || len(target) > 253 || !strings.Contains(target, ".") || net.ParseIP(target) != nil {
		return "", fmt.Errorf("ALIAS target must be an external DNS hostname, not an IP address")
	}
	for _, label := range strings.Split(target, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid ALIAS target hostname")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("invalid ALIAS target hostname")
			}
		}
	}
	target = dns.Fqdn(target)
	if dns.IsSubDomain(zone, target) {
		return "", fmt.Errorf("ALIAS target must be outside %s to avoid DNS loops", zone)
	}
	return target, nil
}

// RefreshAliases resolves only administrator-configured ALIAS targets. Call it
// before making the DNS service ready: an initial resolution failure is fatal.
// Later refresh failures retain the previous answers for at most aliasMaxAge.
func RefreshAliases(ctx context.Context) error {
	mu.RLock()
	pending := make(map[string]*aliasEntry, len(aliases))
	for name, entry := range aliases {
		pending[name] = entry
	}
	mu.RUnlock()
	var failures []error
	for name, entry := range pending {
		lookupCtx, cancel := context.WithTimeout(ctx, aliasLookupTimeout)
		ips, err := aliasLookupIP(lookupCtx, entry.target)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("resolve ALIAS %s -> %s: %w", name, entry.target, err))
			continue
		}
		answers := aliasAddresses(name, ips)
		if len(answers) == 0 {
			failures = append(failures, fmt.Errorf("ALIAS %s -> %s returned no usable IP addresses", name, entry.target))
			continue
		}
		mu.Lock()
		// A concurrent Configure must never receive a stale lookup result.
		if aliases[name] == entry {
			entry.addresses = answers
			entry.refreshedAt = aliasNow()
		}
		mu.Unlock()
	}
	return errors.Join(failures...)
}

// RunAliasRefresh owns no listener and performs no work on the DNS query path.
// Its caller owns the service context and must wait for it during shutdown.
func RunAliasRefresh(ctx context.Context) {
	ticker := time.NewTicker(aliasRefreshPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := RefreshAliases(ctx); err != nil && ctx.Err() == nil {
				logger.Warn("[customdns] %v; cached ALIAS answers expire after %s", err, aliasMaxAge)
			}
		}
	}
}

func aliasAddresses(name string, ips []net.IPAddr) []dns.RR {
	var answers []dns.RR
	seen := make(map[netip.Addr]bool)
	for _, ip := range ips {
		addr, valid := netip.AddrFromSlice(ip.IP)
		if !valid || ip.Zone != "" {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || seen[addr] {
			continue
		}
		seen[addr] = true
		if addr.Is4() {
			answers = append(answers, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: aliasTTL}, A: net.IP(addr.AsSlice())})
		} else {
			answers = append(answers, &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: aliasTTL}, AAAA: net.IP(addr.AsSlice())})
		}
		if len(answers) == 64 {
			break
		}
	}
	return answers
}

func aliasFresh(entry *aliasEntry, now time.Time) bool {
	return len(entry.addresses) != 0 && !entry.refreshedAt.IsZero() && now.Before(entry.refreshedAt.Add(aliasMaxAge))
}

// cachedAliasRecords requires mu to be held and returns independent copies.
func cachedAliasRecords(entry *aliasEntry, kind uint16) []dns.RR {
	now := aliasNow()
	if !aliasFresh(entry, now) {
		return nil
	}
	ttl := aliasTTL
	if remaining := uint32(entry.refreshedAt.Add(aliasMaxAge).Sub(now) / time.Second); remaining < ttl {
		ttl = remaining
	}
	var answers []dns.RR
	for _, rr := range entry.addresses {
		if rr.Header().Rrtype == kind {
			copy := dns.Copy(rr)
			copy.Header().Ttl = ttl
			answers = append(answers, copy)
		}
	}
	return answers
}

// AliasUnavailable tells the DNS handler to return SERVFAIL for an A/AAAA query
// instead of claiming there is no record when an ALIAS cache is absent or stale.
// TXT, MX, SOA and NS answers are independent of ALIAS resolution.
func AliasUnavailable(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	entry := aliases[dns.Fqdn(strings.ToLower(name))]
	return entry != nil && !aliasFresh(entry, aliasNow())
}
