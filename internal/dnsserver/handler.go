package dnsserver

import (
	"github.com/crypto-chiefs/dnsbox/internal/resolver"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	domain := os.Getenv("DNSBOX_DOMAIN")
	ipEnv := os.Getenv("DNSBOX_IP")
	nsNameRaw := os.Getenv("DNSBOX_NS_NAME")
	if domain == "" || ipEnv == "" || nsNameRaw == "" {
		log.Printf("[dnsbox] ❌ Missing env vars: DNSBOX_DOMAIN, DNSBOX_IP, or DNSBOX_NS_NAME")
		return
	}

	nsFQDN := dns.Fqdn(nsNameRaw + "." + domain)

	for _, q := range r.Question {
		qName := strings.ToLower(q.Name)
		log.Printf("[dnsbox] Received query: %s %s", dns.TypeToString[q.Qtype], qName)

		switch q.Qtype {
		case dns.TypeNS:
			if strings.EqualFold(qName, dns.Fqdn(domain)) {
				log.Printf("[dnsbox] NS query matches domain, generating NS record for %s", nsFQDN)
				msg.Authoritative = true
				msg.Answer = append(msg.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain),
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Ns: nsFQDN,
				})
				msg.Extra = append(msg.Extra, &dns.A{
					Hdr: dns.RR_Header{
						Name:   nsFQDN,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP(ipEnv),
				})
			} else {
				log.Printf("[dnsbox] NS query does not match domain: qName=%s ≠ %s", qName, dns.Fqdn(domain))
			}

		case dns.TypeSOA:
			if strings.EqualFold(qName, dns.Fqdn(domain)) {
				msg.Authoritative = true
				msg.Answer = append(msg.Answer, &dns.SOA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain),
						Rrtype: dns.TypeSOA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Ns:      nsFQDN,
					Mbox:    "hostmaster." + domain + ".",
					Serial:  uint32(time.Now().Unix()),
					Refresh: 3600,
					Retry:   600,
					Expire:  86400,
					Minttl:  60,
				})
			}

		case dns.TypeA:
			if ip := resolver.ParseIPv4(qName); ip != nil {
				log.Printf("[dnsbox] A query matched ParseIPv4: %s -> %s", qName, ip.String())
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP(ipEnv),
				})
				break
			}
			if dns.Fqdn(qName) == nsFQDN {
				log.Printf("[dnsbox] A query matched our NS name: %s -> %s", nsFQDN, ipEnv)
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   nsFQDN,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP(ipEnv),
				})
			}

		case dns.TypeAAAA:
			if ip := resolver.ParseIPv6(qName); ip != nil {
				log.Printf("[dnsbox] AAAA query match: %s -> %s", qName, ip.String())
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: net.ParseIP(ipEnv),
				})
			}

		case dns.TypeTXT:
			if value, ok := txtstore.Get(qName); ok {
				log.Printf("[dnsbox] TXT query match: %s -> %s", qName, value)
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{value},
				})
			}
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[dnsbox] failed to write DNS response: %v", err)
	}
}
