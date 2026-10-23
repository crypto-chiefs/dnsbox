package dnsserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/customdns"
	"github.com/miekg/dns"
)

func TestUnavailableAliasDoesNotBecomeNegativeAnswer(t *testing.T) {
	setup(t)
	path := filepath.Join(t.TempDir(), "records")
	if err := os.WriteFile(path, []byte("example.test ALIAS landing.other.test\nexample.test TXT \"retained\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := customdns.Configure(path, config.Domain); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := query(t, "example.test", kind)
		if msg.Rcode != dns.RcodeServerFailure || len(msg.Answer) != 0 || len(msg.Ns) != 0 {
			t.Fatalf("unavailable ALIAS produced a cacheable negative answer: %v", msg)
		}
	}
	for _, kind := range []uint16{dns.TypeTXT, dns.TypeNS, dns.TypeSOA} {
		msg := query(t, "example.test", kind)
		if !msg.Authoritative || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
			t.Fatalf("unavailable ALIAS affected %s: %v", dns.TypeToString[kind], msg)
		}
	}
	msg := query(t, "8.8.8.8.example.test", dns.TypeA)
	if len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != config.IP {
		t.Fatalf("unavailable apex ALIAS affected proxy: %v", msg)
	}
}
