package dnsserver

import (
	"github.com/crypto-chiefs/dnsbox/internal/resolver"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/miekg/dns"
	"log"
	"strings"
)

func handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	for _, q := range r.Question {
		qName := strings.ToLower(q.Name)

		switch q.Qtype {
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
