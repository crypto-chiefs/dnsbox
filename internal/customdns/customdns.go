package customdns

import (
	"bufio"
	"embed"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

//go:embed custom_domains.txt
var embedded embed.FS

type Record struct {
	Type string
	Name string
	Data string
}

var (
	records []Record
	once    sync.Once
)

func Load() {
	once.Do(func() {
		f, err := embedded.Open("custom_domains.txt")
		if err != nil {
			logger.Error("[customdns] ❌ Failed to load embedded custom_domains.txt: %v", err)
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 3 {
				continue
			}
			records = append(records, Record{
				Name: strings.ToLower(parts[0]),
				Type: strings.ToUpper(parts[1]),
				Data: strings.Join(parts[2:], " "),
			})
		}
		logger.Info("[customdns] ✅ Loaded %d custom DNS records", len(records))
	})
}

func Match(name string, qtype uint16) []Record {
	Load()
	var matched []Record
	name = strings.ToLower(name)

	for _, r := range records {
		if r.Name != name {
			continue
		}

		switch qtype {
		case dns.TypeA:
			if r.Type == "A" {
				matched = append(matched, r)
			}
		case dns.TypeTXT:
			if r.Type == "TXT" {
				matched = append(matched, r)
			}
		case dns.TypeCNAME:
			if r.Type == "CNAME" {
				matched = append(matched, r)
			}
		case dns.TypeMX:
			if r.Type == "MX" {
				matched = append(matched, r)
			}
		}
	}

	return matched
}
