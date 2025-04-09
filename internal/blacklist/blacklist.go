package blacklist

import (
	"bufio"
	"embed"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"net"
	"strings"
)

//go:embed blacklist.txt
var rawBlacklist embed.FS

var (
	exactIPs   = map[string]struct{}{}
	cidrBlocks []*net.IPNet
	loaded     bool
)

func LoadEmbedded() {
	if loaded {
		return
	}
	loaded = true

	file, err := rawBlacklist.Open("blacklist.txt")
	if err != nil {
		logger.Error("[blacklist] ❌ Failed to load embedded blacklist: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)

		if strings.Contains(line, "-") && !strings.Contains(line, "/") {
			line = strings.ReplaceAll(line, "-", ".")
		}

		if strings.Contains(line, "/") {
			if _, cidr, err := net.ParseCIDR(line); err == nil {
				cidrBlocks = append(cidrBlocks, cidr)
			}
		} else {
			if ip := net.ParseIP(line); ip != nil {
				exactIPs[ip.String()] = struct{}{}
			}
		}
	}

	logger.Info("[blacklist] ✅ Loaded %d embedded IPs, %d CIDRs", len(exactIPs), len(cidrBlocks))
}

func IsBlocked(ipStr string) bool {
	if !loaded {
		LoadEmbedded()
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if _, found := exactIPs[ip.String()]; found {
		return true
	}
	for _, cidr := range cidrBlocks {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
