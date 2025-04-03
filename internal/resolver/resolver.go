package resolver

import (
	"net"
	"strings"
)

func ParseIPv4(qname string) net.IP {
	qname = strings.TrimSuffix(qname, ".")
	parts := strings.Split(qname, ".")

	if len(parts) < 3 {
		return nil
	}

	// example: 1-2-3-4.dnsbox.io
	ipRaw := parts[0]
	ip := strings.ReplaceAll(ipRaw, "-", ".")

	parsed := net.ParseIP(ip)
	if parsed != nil {
		return parsed.To4()
	}

	// example: 1.2.3.4.dnsbox.io
	ip = strings.Join(parts[:4], ".")
	return net.ParseIP(ip).To4()
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
