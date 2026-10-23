package dnsserver

import (
	"net"
	"strings"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/customdns"
	"github.com/crypto-chiefs/dnsbox/internal/logger"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/miekg/dns"
)

const negativeTTL = 30

func rrHeader(name string, kind uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: kind, Class: dns.ClassINET, Ttl: ttl}
}
func soa() *dns.SOA {
	zone := dns.Fqdn(config.Domain)
	return &dns.SOA{Hdr: rrHeader(zone, dns.TypeSOA, negativeTTL),
		Ns: dns.Fqdn(config.NSName + "." + config.Domain), Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: negativeTTL}
}
func address(name string, kind uint16, ip net.IP) dns.RR {
	if ip == nil {
		return nil
	}
	if kind == dns.TypeA && ip.To4() != nil {
		return &dns.A{Hdr: rrHeader(name, kind, 60), A: ip.To4()}
	}
	if kind == dns.TypeAAAA && ip.To4() == nil {
		return &dns.AAAA{Hdr: rrHeader(name, kind, 60), AAAA: ip.To16()}
	}
	return nil
}

func handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	defer func() {
		// UDP answers are bounded even when a client advertises a huge EDNS
		// buffer. TCP remains available for retrieving the complete answer.
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			size := uint16(dns.MinMsgSize)
			if opt := r.IsEdns0(); opt != nil {
				size = opt.UDPSize()
				if size < dns.MinMsgSize {
					size = dns.MinMsgSize
				}
				if size > 1232 {
					size = 1232
				}
			}
			msg.Truncate(int(size))
		}
		if err := w.WriteMsg(msg); err != nil {
			logger.Debug("[dns] write response: %v", err)
		}
	}()
	if r.Opcode != dns.OpcodeQuery {
		msg.Rcode = dns.RcodeNotImplemented
		return
	}
	if len(r.Question) != 1 {
		msg.Rcode = dns.RcodeFormatError
		return
	}
	if opt := r.IsEdns0(); opt != nil {
		msg.SetEdns0(1232, false)
		if opt.Version() != 0 {
			msg.Rcode = dns.RcodeBadVers
			return
		}
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	zone := dns.Fqdn(strings.ToLower(config.Domain))
	if q.Qclass != dns.ClassINET || !dns.IsSubDomain(zone, name) {
		msg.Rcode = dns.RcodeRefused
		return
	}
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		msg.Rcode = dns.RcodeRefused
		return
	}
	msg.Authoritative = true
	ns := dns.Fqdn(config.NSName + "." + config.Domain)
	isHost := false
	if _, err := config.ValidateHostname(strings.TrimSuffix(name, ".")); err == nil {
		isHost = true
	}
	exists := name == zone || name == ns || isHost || customdns.Exists(name)
	hasCustomAddress := len(customdns.Records(name, dns.TypeA))+len(customdns.Records(name, dns.TypeAAAA)) > 0
	if strings.HasPrefix(name, "_acme-challenge.") {
		if _, err := config.ValidateHostname(strings.TrimSuffix(strings.TrimPrefix(name, "_acme-challenge."), ".")); err == nil {
			exists = true
		}
	}
	// CNAMEs apply to every query type, not just A queries.
	if cnames := customdns.Records(name, dns.TypeCNAME); len(cnames) > 0 {
		msg.Answer = cnames
		return
	}
	if q.Qtype == dns.TypeTXT {
		if value, ok := txtstore.Get(name); ok {
			parts := []string{}
			for len(value) > 255 {
				parts = append(parts, value[:255])
				value = value[255:]
			}
			parts = append(parts, value)
			msg.Answer = append(msg.Answer, &dns.TXT{Hdr: rrHeader(q.Name, dns.TypeTXT, 1), Txt: parts})
			exists = true
		}
	}
	msg.Answer = append(msg.Answer, customdns.Records(name, q.Qtype)...)
	if len(msg.Answer) > 0 {
		return
	}
	switch q.Qtype {
	case dns.TypeSOA:
		if name == zone {
			msg.Answer = append(msg.Answer, soa())
		}
	case dns.TypeNS:
		if name == zone {
			msg.Answer = append(msg.Answer, &dns.NS{Hdr: rrHeader(q.Name, dns.TypeNS, 300), Ns: ns})
			glue := append(customdns.Records(ns, dns.TypeA), customdns.Records(ns, dns.TypeAAAA)...)
			if len(glue) > 0 {
				msg.Extra = append(msg.Extra, glue...)
			} else {
				for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
					if rr := address(ns, kind, net.ParseIP(config.IP)); rr != nil {
						msg.Extra = append(msg.Extra, rr)
					}
				}
			}
		}
	case dns.TypeA, dns.TypeAAAA:
		if (name == ns || isHost) && !hasCustomAddress {
			// The encoded address identifies the backend. Clients connect to
			// DNSBox itself, where HTTPS is terminated and proxied over HTTP.
			if rr := address(q.Name, q.Qtype, net.ParseIP(config.IP)); rr != nil {
				msg.Answer = append(msg.Answer, rr)
			}
		}
	case dns.TypeANY:
		if exists {
			msg.Answer = append(msg.Answer, &dns.HINFO{Hdr: rrHeader(q.Name, dns.TypeHINFO, 60), Cpu: "RFC8482", Os: ""})
		}
	}
	if len(msg.Answer) == 0 {
		if !exists {
			msg.Rcode = dns.RcodeNameError
		}
		msg.Ns = append(msg.Ns, soa())
	}
}
