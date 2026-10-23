package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Nameserver is an authoritative server's hostname and advertised IP address.
// Name has no trailing dot. Both fields are canonicalized during validation.
type Nameserver struct {
	Name string
	IP   string
}

var authoritativeNameservers []Nameserver

func validateNameservers() error {
	authoritativeNameservers = nil
	if !validDNSName(NSName + "." + Domain) {
		return fmt.Errorf("nameserver hostname exceeds DNS name limits")
	}
	if Nameservers == "" {
		return nil
	}
	var servers []Nameserver
	seen := make(map[string]bool)
	localFound := false
	for _, item := range strings.Split(Nameservers, ",") {
		label, rawIP, ok := strings.Cut(strings.TrimSpace(item), "=")
		label = strings.ToLower(strings.TrimSpace(label))
		if !ok || !validDNSName(label) || strings.Contains(label, ".") || !validDNSName(label+"."+Domain) {
			return fmt.Errorf("invalid --nameservers entry %q: expected label=IP", item)
		}
		if seen[label] {
			return fmt.Errorf("duplicate --nameservers label %q", label)
		}
		address, err := netip.ParseAddr(strings.TrimSpace(rawIP))
		if err != nil || address.Zone() != "" || (!address.IsGlobalUnicast() && !address.IsLoopback()) {
			return fmt.Errorf("invalid --nameservers address for %s: expected a unicast IP", label)
		}
		canonicalIP := address.Unmap().String()
		if label == NSName {
			localFound = true
			if canonicalIP != IP {
				return fmt.Errorf("--nameservers address for local server %s must match --ip (%s)", label, IP)
			}
		}
		seen[label] = true
		servers = append(servers, Nameserver{Name: label + "." + Domain, IP: canonicalIP})
	}
	if !localFound {
		return fmt.Errorf("--nameservers must include local server %s", NSName)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	authoritativeNameservers = servers
	return nil
}

// AuthoritativeNameservers returns a copy sorted by hostname, so all nodes with
// the same roster publish the same NS records and select the same SOA primary.
func AuthoritativeNameservers() []Nameserver {
	if Nameservers == "" {
		return []Nameserver{{Name: NSName + "." + Domain, IP: IP}}
	}
	return append([]Nameserver(nil), authoritativeNameservers...)
}
