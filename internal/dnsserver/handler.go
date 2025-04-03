package dnsserver

import (
	"fmt"
	"github.com/crypto-chiefs/dnsbox/internal/resolver"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/crypto-chiefs/dnsbox/internal/utils"
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

	for _, q := range r.Question {
		qName := strings.ToLower(q.Name)

		switch q.Qtype {
		case dns.TypeNS:
			domain := os.Getenv("DNSBOX_DOMAIN")
			if domain == "" {
				log.Printf("DNSBOX_DOMAIN is not set")
				break
			}

			// Убедимся, что запрос по нужному домену
			if strings.EqualFold(qName, dns.Fqdn(domain)) {
				msg.Authoritative = true

				peers, err := utils.DiscoverPeers()
				if err != nil {
					log.Printf("failed to discover peers: %v", err)
					break
				}

				for i, ip := range peers {
					nsName := fmt.Sprintf("ns%d.%s.", i+1, domain)

					msg.Answer = append(msg.Answer, &dns.NS{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(domain),
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns: nsName,
					})

					msg.Extra = append(msg.Extra, &dns.A{
						Hdr: dns.RR_Header{
							Name:   nsName,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.ParseIP(ip),
					})
				}
			}

		case dns.TypeSOA:
			domain := os.Getenv("DNSBOX_DOMAIN")
			if domain == "" {
				log.Printf("DNSBOX_DOMAIN is not set")
				break
			}

			if strings.EqualFold(qName, dns.Fqdn(domain)) {
				msg.Authoritative = true

				// The first NS is for SOA (if there are no peers— we give an empty stub)
				nsName := "ns1." + domain + "."
				mailbox := "hostmaster." + domain + "."

				// Ideally, it's better to get peers and use the first one.
				peers, err := utils.DiscoverPeers()
				if err != nil || len(peers) == 0 {
					log.Printf("failed to get peers for SOA: %v", err)
				} else {
					nsName = "ns1." + domain + "."
				}

				msg.Answer = append(msg.Answer, &dns.SOA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain),
						Rrtype: dns.TypeSOA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Ns:      nsName,
					Mbox:    mailbox,
					Serial:  uint32(time.Now().Unix()), // dynamic serial number (can be replaced with a stable hash)
					Refresh: 3600,
					Retry:   600,
					Expire:  86400,
					Minttl:  60,
				})
			}

		case dns.TypeA:
			if ip := resolver.ParseIPv4(qName); ip != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: ip,
				})
			}

		case dns.TypeAAAA:
			if ip := resolver.ParseIPv6(q.Name); ip != nil {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: ip,
				})
			}

		case dns.TypeTXT:
			if value, ok := txtstore.Get(qName); ok {
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
		log.Printf("failed to write DNS response: %v", err)
	}
}
