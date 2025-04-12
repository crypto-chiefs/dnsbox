package dnsserver

import (
	"github.com/crypto-chiefs/dnsbox/internal/blacklist"
	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/customdns"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/crypto-chiefs/dnsbox/internal/resolver"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/crypto-chiefs/dnsbox/internal/utils"
	"github.com/miekg/dns"
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

	nsFQDN := dns.Fqdn(nsNameRaw + "." + domain)

	for _, q := range r.Question {
		qName := strings.ToLower(q.Name)
		logger.Info("[dnsbox] Received query: %s %s", dns.TypeToString[q.Qtype], qName)

		switch q.Qtype {
		case dns.TypeNS:
			if strings.EqualFold(qName, dns.Fqdn(domain)) {
				logger.Info("[dnsbox] NS query matches domain, generating NS record for %s", nsFQDN)
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
					logger.Error("[dnsbox] ❌ Failed to discover peers, falling back to static NS: %s (%s)", nsNameRaw, ipEnv)

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
				logger.Info("[dnsbox] NS query does not match domain: qName=%s ≠ %s", qName, dns.Fqdn(domain))
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
			matched := customdns.Match(qName, dns.TypeA)
			if len(matched) > 0 {
				for _, r := range matched {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(r.Name),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.ParseIP(r.Data),
					})
				}
				msg.Authoritative = true
				break
			}

			cnames := customdns.Match(qName, dns.TypeCNAME)
			if len(cnames) > 0 {
				for _, r := range cnames {
					msg.Answer = append(msg.Answer, &dns.CNAME{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(r.Name),
							Rrtype: dns.TypeCNAME,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Target: dns.Fqdn(r.Data),
					})
				}
				msg.Authoritative = true
				break
			}

			if ip := resolver.ParseIPv4(qName); ip != nil {
				ipStr := ip.String()

				if blacklist.IsBlocked(ipStr) {
					logger.Warn("[dnsbox] ❌ Blocked A query: %s → blacklisted %s", qName, ipStr)
					break
				}

				logger.Info("[dnsbox] A query matched ParseIPv4: %s -> %s", qName, ip.String())
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
				if blacklist.IsBlocked(ipEnv) {
					logger.Warn("[dnsbox] ❌ Blocked A query for NS %s → blacklisted %s", nsFQDN, ipEnv)
					break
				}
				logger.Info("[dnsbox] A query matched our NS name: %s -> %s", nsFQDN, ipEnv)
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   nsFQDN,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP(ipEnv),
				})
				break
			}

		case dns.TypeAAAA:
			matched := customdns.Match(qName, dns.TypeAAAA)
			if len(matched) > 0 {
				for _, r := range matched {
					logger.Info("[dnsbox] AAAA query match (custom): %s -> %s", r.Name, r.Data)
					msg.Answer = append(msg.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(r.Name),
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						AAAA: net.ParseIP(r.Data),
					})
				}
				msg.Authoritative = true
				break
			}

			if ip := resolver.ParseIPv6(qName); ip != nil {
				ipStr := ip.String()
				if blacklist.IsBlocked(ipStr) {
					logger.Warn("[dnsbox] ❌ Blocked AAA query: %s → blacklisted %s", qName, ipStr)
					break
				}

				logger.Info("[dnsbox] AAAA query match: %s -> %s", qName, ip.String())
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
				logger.Info("[dnsbox] TXT query match (store): %s -> %s", qName, value)
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{value},
				})
				msg.Authoritative = true
				break
			}

			matched := customdns.Match(qName, dns.TypeTXT)
			if len(matched) > 0 {
				for _, r := range matched {
					logger.Info("[dnsbox] TXT query match (custom): %s -> %s", r.Name, r.Data)
					msg.Answer = append(msg.Answer, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(r.Name),
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						Txt: []string{r.Data},
					})
				}
				msg.Authoritative = true
			}

		case dns.TypeSRV:
			logger.Info("[dnsbox] SRV query detected for: %s", qName)
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
			matched := customdns.Match(qName, dns.TypeCNAME)
			if len(matched) > 0 {
				for _, r := range matched {
					logger.Info("[dnsbox] CNAME query detected for: %s (fallback → %s)", qName, domain)
					msg.Answer = append(msg.Answer, &dns.CNAME{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(r.Name),
							Rrtype: dns.TypeCNAME,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Target: dns.Fqdn(r.Data),
					})
				}
				msg.Authoritative = true
				break
			}

			logger.Info("[dnsbox] CNAME query detected for: %s (fallback → %s)", qName, domain)
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: dns.Fqdn(domain),
			})
			msg.Authoritative = true

		case dns.TypeMX:
			matched := customdns.Match(qName, dns.TypeMX)
			if len(matched) > 0 {
				for _, r := range matched {
					logger.Info("[dnsbox] MX query matched (custom): %s → %s", r.Name, r.Data)
					msg.Answer = append(msg.Answer, &dns.MX{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(r.Name),
							Rrtype: dns.TypeMX,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Preference: 10,
						Mx:         dns.Fqdn(r.Data),
					})
					msg.Extra = append(msg.Extra, &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(r.Data),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.ParseIP(ipEnv),
					})
				}
				msg.Authoritative = true
				break
			}

			logger.Info("[dnsbox] MX query detected for: %s (fallback)", qName)
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
			msg.Authoritative = true
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		logger.Error("[dnsbox] failed to write DNS response: %v", err)
	}
}
