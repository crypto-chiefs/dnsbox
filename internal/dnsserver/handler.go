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
		log.Printf("[dnsbox] Received query: %s %s", dns.TypeToString[q.Qtype], qName)

		switch q.Qtype {
		case dns.TypeNS:
			domain := os.Getenv("DNSBOX_DOMAIN")
			log.Printf("[dnsbox] DNSBOX_DOMAIN = %s, fqdn = %s", domain, dns.Fqdn(domain))

			if domain == "" {
				log.Printf("[dnsbox] DNSBOX_DOMAIN is not set")
				break
			}

			if strings.EqualFold(qName, dns.Fqdn(domain)) {
				log.Printf("[dnsbox] NS query matches domain, generating NS records...")
				msg.Authoritative = true

				peers, err := utils.DiscoverPeers()
				if err != nil {
					log.Printf("[dnsbox] failed to discover peers: %v", err)
					//Setting a forced peers if NS does not already have a glue record
					peers = []string{os.Getenv("DNSBOX_IP")}
				}

				log.Printf("[dnsbox] Discovered peers: %v", peers)

				if len(peers) == 0 {
					log.Printf("[dnsbox] No peers discovered — using fallback to DNSBOX_IP: %s", os.Getenv("DNSBOX_IP"))
					//Setting a forced peers if NS does not already have a glue record
					peers = []string{os.Getenv("DNSBOX_IP")}
				}

				for i, ip := range peers {
					nsName := fmt.Sprintf("ns%d.%s.", i+1, domain)
					log.Printf("[dnsbox] Adding NS record: %s -> %s", domain, nsName)

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
			} else {
				log.Printf("[dnsbox] NS query does not match domain: qName=%s ≠ %s", qName, dns.Fqdn(domain))
			}

		case dns.TypeSOA:
			domain := os.Getenv("DNSBOX_DOMAIN")
			if domain == "" {
				log.Printf("[dnsbox] DNSBOX_DOMAIN is not set")
				break
			}

			if strings.EqualFold(qName, dns.Fqdn(domain)) {
				msg.Authoritative = true

				nsName := "ns1." + domain + "."
				mailbox := "hostmaster." + domain + "."

				peers, err := utils.DiscoverPeers()
				if err != nil || len(peers) == 0 {
					log.Printf("[dnsbox] SOA peer fallback used due to error or empty peer list: %v", err)
				} else {
					log.Printf("[dnsbox] SOA using peers, first: %s", peers[0])
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
					Serial:  uint32(time.Now().Unix()),
					Refresh: 3600,
					Retry:   600,
					Expire:  86400,
					Minttl:  60,
				})
			}

		case dns.TypeA:
			domain := os.Getenv("DNSBOX_DOMAIN")
			ipEnv := os.Getenv("DNSBOX_IP")

			if ip := resolver.ParseIPv4(qName); ip != nil {
				log.Printf("[dnsbox] A query matched by ParseIPv4: %s -> %s", qName, ip.String())
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: ip,
				})
				break // Уже ответили, дальше не идем
			}

			peers, err := utils.DiscoverPeers()
			if err != nil || len(peers) == 0 {
				log.Printf("[dnsbox] DiscoverPeers failed (%v), using fallback IP", err)
				peers = []string{ipEnv}
			}

			for i, peerIP := range peers {
				nsName := fmt.Sprintf("ns%d.%s.", i+1, domain)
				log.Printf("[dnsbox] Comparing A query: %q vs nsName: %q", dns.Fqdn(qName), dns.Fqdn(nsName))

				if dns.Fqdn(qName) == dns.Fqdn(nsName) {
					ip := net.ParseIP(peerIP)
					if ip == nil {
						log.Printf("[dnsbox] Invalid peer IP: %q — skipping", peerIP)
						continue
					}
					log.Printf("[dnsbox] A query matched peer NS: %s → %s", nsName, ip.String())
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   nsName,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: ip,
					})
					break
				}
			}

			log.Printf("[dnsbox] A query did not match any known IP: %s", qName)

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
					AAAA: ip,
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
