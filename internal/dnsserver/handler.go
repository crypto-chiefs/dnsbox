package dnsserver

import (
	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/resolver"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/crypto-chiefs/dnsbox/internal/utils"
	"github.com/miekg/dns"
	"log"
	"net"
	"strings"
	"time"
)

func handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	domain := config.Domain
	ipEnv := config.IP
	nsNameRaw := config.NSName
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

				peers, err := utils.DiscoverPeers()
				if err == nil && len(peers) > 0 {
					for _, peer := range peers {
						nsFqdn := dns.Fqdn(peer.Name)
						msg.Answer = append(msg.Answer, &dns.NS{
							Hdr: dns.RR_Header{
								Name:   dns.Fqdn(domain),
								Rrtype: dns.TypeNS,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Ns: nsFqdn,
						})
						msg.Extra = append(msg.Extra, &dns.A{
							Hdr: dns.RR_Header{
								Name:   nsFqdn,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.ParseIP(peer.IP),
						})
					}
				} else {
					log.Printf("[dnsbox] ❌ Failed to discover peers, falling back to static NS: %s (%s)", nsNameRaw, ipEnv)

					nsFQDN := dns.Fqdn(nsNameRaw + "." + domain)

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
				}
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

		case dns.TypeSRV:
			log.Printf("[dnsbox] SRV query detected for: %s", qName)
			if strings.HasSuffix(dns.Fqdn(qName), dns.Fqdn(domain)) {
				peers, err := utils.DiscoverPeers()
				if err == nil && len(peers) > 0 {
					for i, peer := range peers {
						target := dns.Fqdn(peer.Name)
						msg.Answer = append(msg.Answer, &dns.SRV{
							Hdr: dns.RR_Header{
								Name:   qName,
								Rrtype: dns.TypeSRV,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Priority: uint16(10 + i),
							Weight:   10,
							Port:     443,
							Target:   target,
						})
						msg.Extra = append(msg.Extra, &dns.A{
							Hdr: dns.RR_Header{
								Name:   target,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.ParseIP(peer.IP),
						})
					}
					break
				}
			}

			msg.Answer = append(msg.Answer, &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 10,
				Weight:   10,
				Port:     443,
				Target:   dns.Fqdn(domain),
			})
			msg.Extra = append(msg.Extra, &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(domain),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(ipEnv),
			})

		case dns.TypeCNAME:
			log.Printf("[dnsbox] CNAME query detected for: %s", qName)
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: dns.Fqdn(domain),
			})

		case dns.TypeMX:
			log.Printf("[dnsbox] MX query detected for: %s", qName)
			msg.Answer = append(msg.Answer, &dns.MX{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Preference: 10,
				Mx:         "mail." + domain + ".",
			})
			msg.Extra = append(msg.Extra, &dns.A{
				Hdr: dns.RR_Header{
					Name:   "mail." + domain + ".",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(ipEnv),
			})
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[dnsbox] failed to write DNS response: %v", err)
	}
}
