package dnsserver

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/customdns"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/miekg/dns"
)

func recordStrings(records []dns.RR) []string {
	result := make([]string, len(records))
	for i, rr := range records {
		result[i] = rr.String()
	}
	return result
}

func TestAllNodesPublishTheSameAuthority(t *testing.T) {
	setup(t)
	servers := []struct{ label, ip, roster string }{
		{"ns1", "134.199.248.116", "ns3=167.172.5.205,ns1=134.199.248.116,ns2=143.244.206.240"},
		{"ns2", "143.244.206.240", "ns2=143.244.206.240,ns3=167.172.5.205,ns1=134.199.248.116"},
		{"ns3", "167.172.5.205", "ns1=134.199.248.116,ns2=143.244.206.240,ns3=167.172.5.205"},
	}
	var firstNS, firstGlue, firstSOA []string
	for i, server := range servers {
		if err := config.Load([]string{"--domain=example.test", "--ip=" + server.ip, "--ns=" + server.label, "--nameservers=" + server.roster}); err != nil {
			t.Fatal(err)
		}
		ns := query(t, "example.test", dns.TypeNS)
		soa := query(t, "example.test", dns.TypeSOA)
		if !ns.Authoritative || ns.Truncated || len(ns.Answer) != 3 || len(ns.Extra) != 3 || !soa.Authoritative || len(soa.Answer) != 1 {
			t.Fatalf("%s: incomplete authority: NS=%v SOA=%v", server.label, ns, soa)
		}
		if primary := soa.Answer[0].(*dns.SOA).Ns; primary != "ns1.example.test." {
			t.Fatalf("%s: primary is %s", server.label, primary)
		}
		if i == 0 {
			firstNS, firstGlue, firstSOA = recordStrings(ns.Answer), recordStrings(ns.Extra), recordStrings(soa.Answer)
		} else if !reflect.DeepEqual(recordStrings(ns.Answer), firstNS) || !reflect.DeepEqual(recordStrings(ns.Extra), firstGlue) || !reflect.DeepEqual(recordStrings(soa.Answer), firstSOA) {
			t.Fatalf("%s authority differs: NS=%v SOA=%v", server.label, ns, soa)
		}
		for _, peer := range servers {
			msg := query(t, peer.label+".example.test", dns.TypeA)
			if !msg.Authoritative || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != peer.ip {
				t.Fatalf("%s did not answer %s: %v", server.label, peer.label, msg)
			}
			msg = query(t, peer.label+".example.test", dns.TypeAAAA)
			if !msg.Authoritative || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 || !reflect.DeepEqual(recordStrings(msg.Ns), firstSOA) {
				t.Fatalf("%s invented IPv6 for %s: %v", server.label, peer.label, msg)
			}
		}
		msg := query(t, "8.8.8.8.example.test", dns.TypeA)
		if len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != server.ip {
			t.Fatalf("%s lost local proxy address: %v", server.label, msg)
		}
	}
}

func TestClusterNameserverFamiliesAndCustomOverrides(t *testing.T) {
	setup(t)
	if err := config.Load([]string{"--domain=example.test", "--ip=203.0.113.10", "--nameservers=ns1=203.0.113.10,ns2=2001:db8::53,ns3=192.0.2.53"}); err != nil {
		t.Fatal(err)
	}
	msg := query(t, "ns2.example.test", dns.TypeAAAA)
	if len(msg.Answer) != 1 || msg.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::53" {
		t.Fatalf("IPv6 peer address: %v", msg)
	}
	msg = query(t, "ns2.example.test", dns.TypeA)
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 || len(msg.Ns) != 1 {
		t.Fatalf("IPv6 peer got local IPv4 fallback: %v", msg)
	}
	path := filepath.Join(t.TempDir(), "records")
	if err := os.WriteFile(path, []byte("ns2.example.test A 192.0.2.153\nns3.example.test AAAA 2001:db8::153\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := customdns.Configure(path, config.Domain); err != nil {
		t.Fatal(err)
	}
	msg = query(t, "example.test", dns.TypeNS)
	if len(msg.Extra) != 3 || msg.Extra[1].(*dns.A).A.String() != "192.0.2.153" || msg.Extra[2].(*dns.AAAA).AAAA.String() != "2001:db8::153" {
		t.Fatalf("custom peer glue not honored: %v", msg)
	}
	for _, tc := range []struct {
		name string
		kind uint16
	}{
		{"ns2.example.test", dns.TypeAAAA},
		{"ns3.example.test", dns.TypeA},
	} {
		msg = query(t, tc.name, tc.kind)
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 || len(msg.Ns) != 1 {
			t.Fatalf("custom peer retained original family: %v", msg)
		}
	}
	msg = query(t, "ns2.example.test", dns.TypeA)
	if len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != "192.0.2.153" {
		t.Fatalf("custom peer direct answer differs from glue: %v", msg)
	}
}

func TestConcurrentTXTValuesRemainSeparateRecords(t *testing.T) {
	setup(t)
	name := "_acme-challenge.8.8.8.8.example.test"
	longValue := strings.Repeat("z", 300)
	for _, value := range []string{longValue, "second-challenge"} {
		if err := txtstore.Add(name, value, 60); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { txtstore.Delete(name) })
	msg := query(t, name, dns.TypeTXT)
	if msg.Truncated || len(msg.Answer) != 2 {
		t.Fatalf("concurrent TXT records: %v", msg)
	}
	if first, second := msg.Answer[0].(*dns.TXT), msg.Answer[1].(*dns.TXT); strings.Join(first.Txt, "") != "second-challenge" || strings.Join(second.Txt, "") != longValue || len(second.Txt) != 2 || len(second.Txt[0]) != 255 {
		t.Fatalf("TXT values combined or incorrectly split: %v", msg)
	}
	txtstore.DeleteValue(name, "second-challenge")
	msg = query(t, name, dns.TypeTXT)
	if len(msg.Answer) != 1 || strings.Join(msg.Answer[0].(*dns.TXT).Txt, "") != longValue {
		t.Fatalf("one challenge cleanup removed another: %v", msg)
	}
}
