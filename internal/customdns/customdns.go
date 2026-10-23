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
)

// Configure replaces the record set only after the entire file has validated.
// An empty path means there are no custom records. No deployment-specific
// records are embedded in the executable.
func Configure(path, zone string) error {
	next := make(map[string][]dns.RR)
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open custom records: %w", err)
		}
		defer f.Close()
		next, err = parse(f, zone)
		if err != nil {
			return err
		}
	}
	mu.Lock()
	records = next
	mu.Unlock()
	return nil
}

func parse(r io.Reader, zone string) (map[string][]dns.RR, error) {
	zone = dns.Fqdn(strings.ToLower(zone))
	result := make(map[string][]dns.RR)
	scanner := bufio.NewScanner(r)
	count := 0
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		fail := func(err error) (map[string][]dns.RR, error) {
			return nil, fmt.Errorf("custom records line %d: %w", lineNo, err)
		}
		if len(fields) < 3 {
			return fail(fmt.Errorf("expected name, type and value"))
		}
		name := dns.Fqdn(strings.ToLower(fields[0]))
		if _, ok := dns.IsDomainName(name); !ok || !dns.IsSubDomain(zone, name) || strings.Contains(name, "*") {
			return fail(fmt.Errorf("record name must be inside %s", zone))
		}
		kind := strings.ToUpper(fields[1])
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
		for _, old := range result[name] {
			if old.Header().Rrtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeCNAME {
				return fail(fmt.Errorf("CNAME cannot coexist with another record"))
			}
		}
		result[name] = append(result[name], rr)
		count++
		if count > 10000 {
			return fail(fmt.Errorf("too many records"))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read custom records: %w", err)
	}
	return result, nil
}

// Records returns independent record copies so DNS response construction cannot
// mutate the shared configuration.
func Records(name string, qtype uint16) []dns.RR {
	mu.RLock()
	defer mu.RUnlock()
	var matched []dns.RR
	for _, rr := range records[dns.Fqdn(strings.ToLower(name))] {
		if rr.Header().Rrtype == qtype {
			matched = append(matched, dns.Copy(rr))
		}
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
