// Package resolver decodes backend IP addresses from names in a DNSBox zone.
package resolver

import (
	"fmt"
	"net"
	"strings"
)

// ParseHost accepts only an IP encoding immediately below zone. It deliberately
// does not perform DNS lookups, so a request cannot redirect a proxy via rebinding.
func ParseHost(host, zone string) (net.IP, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" || host == "" || len(host) > 253 || !strings.HasSuffix(host, "."+zone) {
		return nil, fmt.Errorf("hostname is outside the configured zone")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid hostname label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, fmt.Errorf("invalid hostname character")
			}
		}
	}
	encoded := strings.TrimSuffix(host, "."+zone)
	var ip net.IP
	switch {
	case strings.Contains(encoded, "."):
		// Four decimal labels, with no extra service labels.
		if len(strings.Split(encoded, ".")) == 4 {
			ip = net.ParseIP(encoded)
		}
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 encoding")
		}
	case strings.Count(encoded, "-") == 3 && !strings.Contains(encoded, "--"):
		ip = net.ParseIP(strings.ReplaceAll(encoded, "-", "."))
		if ip == nil {
			ip = net.ParseIP(strings.ReplaceAll(encoded, "-", ":"))
		}
	default:
		ip = net.ParseIP(strings.ReplaceAll(encoded, "-", ":"))
	}
	if ip == nil {
		return nil, fmt.Errorf("hostname does not encode an IP address")
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, nil
	}
	return ip.To16(), nil
}

// ParseIPv4 and ParseIPv6 are retained for callers which only need decoding.
// Network-facing callers must use ParseHost with their configured zone.
func ParseIPv4(qname string) net.IP {
	parts := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(parts) < 2 {
		return nil
	}
	if ip := net.ParseIP(strings.ReplaceAll(parts[0], "-", ".")); ip != nil {
		return ip.To4()
	}
	if len(parts) > 4 {
		if ip := net.ParseIP(strings.Join(parts[:4], ".")); ip != nil {
			return ip.To4()
		}
	}
	return nil
}

func ParseIPv6(qname string) net.IP {
	parts := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(parts) < 2 {
		return nil
	}
	ip := net.ParseIP(strings.ReplaceAll(parts[0], "-", ":"))
	if ip == nil || ip.To4() != nil {
		return nil
	}
	return ip.To16()
}
