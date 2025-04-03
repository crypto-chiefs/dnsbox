package resolver

import (
	"net"
	"strings"
)

func ParseIPv4(qname string) net.IP {
	qname = strings.TrimSuffix(qname, ".")
	parts := strings.Split(qname, ".")

	if len(parts) < 2 {
		return nil
	}

	// example: 1-2-3-4.dnsbox.io — DNSBox-syntax
	if len(parts[0]) > 0 && strings.Count(parts[0], "-") == 3 {
		ip := strings.ReplaceAll(parts[0], "-", ".")
		if parsed := net.ParseIP(ip); parsed != nil {
			return parsed.To4()
		}
	}

	// fallback: example 1.2.3.4.dnsbox.io
	if len(parts) >= 4 {
		ip := strings.Join(parts[:4], ".")
		if parsed := net.ParseIP(ip); parsed != nil {
			return parsed.To4()
		}
	}

	return nil
}

func ParseIPv6(qname string) net.IP {
	qname = strings.TrimSuffix(qname, ".")
	parts := strings.Split(qname, ".")

	// example: 2a01-4f8-c17-b8f--1.dnsbox.io → 2a01:4f8:c17:b8f::1
	ipRaw := parts[0]

	// IPv6 `--` replace to `::`
	ip := strings.ReplaceAll(ipRaw, "--", "::")
	ip = strings.ReplaceAll(ip, "-", ":")

	parsed := net.ParseIP(ip)
	if parsed != nil {
		return parsed.To16()
	}

	return nil
}
