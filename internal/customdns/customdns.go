// Package customdns loads administrator-owned records for the configured zone.
package customdns

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type Record struct{ Type, Name, Data string }

var (
	mu      sync.RWMutex
	records = make(map[string][]dns.RR)
	aliases = make(map[string]*aliasEntry)
)

// Configure replaces the record set only after the entire file has validated.
// An empty path means there are no custom records. No deployment-specific
// records are embedded in the executable.
func Configure(path, zone string) error {
	next := make(map[string][]dns.RR)
	nextAliases := make(map[string]string)
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open custom records: %w", err)
		}
		defer f.Close()
		next, nextAliases, err = parseConfig(f, zone)
		if err != nil {
			return err
		}
	}
	mu.Lock()
	records = next
	aliases = make(map[string]*aliasEntry, len(nextAliases))
	for name, target := range nextAliases {
		aliases[name] = &aliasEntry{target: target}
	}
	mu.Unlock()
	return nil
}

func parse(r io.Reader, zone string) (map[string][]dns.RR, error) {
	parsed, _, err := parseConfig(r, zone)
	return parsed, err
}

func parseConfig(r io.Reader, zone string) (map[string][]dns.RR, map[string]string, error) {
	zone = dns.Fqdn(strings.ToLower(zone))
	result := make(map[string][]dns.RR)
	aliasTargets := make(map[string]string)
	scanner := bufio.NewScanner(r)
	count := 0
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		fail := func(err error) (map[string][]dns.RR, map[string]string, error) {
			return nil, nil, fmt.Errorf("custom records line %d: %w", lineNo, err)
		}
		if len(fields) < 3 {
			return fail(fmt.Errorf("expected name, type and value"))
		}
		name := dns.Fqdn(strings.ToLower(fields[0]))
		if _, ok := dns.IsDomainName(name); !ok || !dns.IsSubDomain(zone, name) || strings.Contains(name, "*") {
			return fail(fmt.Errorf("record name must be inside %s", zone))
		}
		kind := strings.ToUpper(fields[1])
		count++
		if count > 10000 {
			return fail(fmt.Errorf("too many records"))
		}
		if kind == "ALIAS" {
			if name != zone || len(fields) != 3 {
				return fail(fmt.Errorf("ALIAS requires the zone apex and exactly one external hostname"))
			}
			target, err := validateAliasTarget(fields[2], zone)
			if err != nil {
				return fail(err)
			}
			if _, exists := aliasTargets[name]; exists {
				return fail(fmt.Errorf("only one ALIAS target is allowed"))
			}
			for _, old := range result[name] {
				if conflictsWithAlias(old.Header().Rrtype) {
					return fail(fmt.Errorf("ALIAS cannot coexist with A, AAAA or CNAME"))
				}
			}
			aliasTargets[name] = target
			continue
		}
		switch kind {
		case "A", "AAAA", "TXT", "MX", "CNAME":
		default:
			return fail(fmt.Errorf("unsupported record type %s", kind))
		}
		// Slice off the first two tokens without destroying quoted TXT spaces.
		data := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		data = strings.TrimSpace(strings.TrimPrefix(data, fields[1]))
		if kind == "MX" {
			if _, err := strconv.ParseUint(fields[2], 10, 16); err != nil {
				data = "10 " + data
			}
		}
		rr, err := dns.NewRR(name + " 300 IN " + kind + " " + data)
		if err != nil {
			return fail(err)
		}
		if kind == "CNAME" && name == zone {
			return fail(fmt.Errorf("zone apex cannot be a CNAME"))
		}
		if _, exists := aliasTargets[name]; exists && conflictsWithAlias(rr.Header().Rrtype) {
			return fail(fmt.Errorf("ALIAS cannot coexist with A, AAAA or CNAME"))
		}
		for _, old := range result[name] {
			if old.Header().Rrtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeCNAME {
				return fail(fmt.Errorf("CNAME cannot coexist with another record"))
			}
		}
		result[name] = append(result[name], rr)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read custom records: %w", err)
	}
	return result, aliasTargets, nil
}

// Records returns independent record copies so DNS response construction cannot
// mutate the shared configuration.
func Records(name string, qtype uint16) []dns.RR {
	mu.RLock()
	defer mu.RUnlock()
	name = dns.Fqdn(strings.ToLower(name))
	var matched []dns.RR
	for _, rr := range records[name] {
		if rr.Header().Rrtype == qtype {
			matched = append(matched, dns.Copy(rr))
		}
	}
	if entry := aliases[name]; entry != nil && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		matched = append(matched, cachedAliasRecords(entry, qtype)...)
	}
	return matched
}

func Exists(name string) bool {
	name = dns.Fqdn(strings.ToLower(name))
	mu.RLock()
	defer mu.RUnlock()
	if _, ok := records[name]; ok {
		return true
	}
	if _, ok := aliases[name]; ok {
		return true
	}
	for n := range records {
		if dns.IsSubDomain(name, n) {
			return true
		}
	}
	return false
}

// Load and Match preserve the old read interface. Loading is now explicit at
// startup through Configure, so a bad configuration cannot fail silently.
func Load() {}
func Match(name string, qtype uint16) []Record {
	var result []Record
	for _, rr := range Records(name, qtype) {
		fields := strings.SplitN(rr.String(), "\t", 5)
		data := ""
		if len(fields) == 5 {
			data = fields[4]
		}
		result = append(result, Record{Type: dns.TypeToString[qtype], Name: rr.Header().Name, Data: data})
	}
	return result
}
