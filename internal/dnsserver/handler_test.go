package dnsserver

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/config"
	"github.com/crypto-chiefs/dnsbox/internal/customdns"
	"github.com/crypto-chiefs/dnsbox/internal/txtstore"
	"github.com/miekg/dns"
)

type responseWriter struct{ msg *dns.Msg }

func (w *responseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *responseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (w *responseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m.Copy(); return nil }
func (w *responseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *responseWriter) Close() error                { return nil }
func (w *responseWriter) TsigStatus() error           { return nil }
func (w *responseWriter) TsigTimersOnly(bool)         {}
func (w *responseWriter) Hijack()                     {}

func setup(t *testing.T) {
	t.Helper()
	oldDomain, oldIP, oldNS, oldNameservers := config.Domain, config.IP, config.NSName, config.Nameservers
	config.Domain = "example.test"
	config.IP = "203.0.113.10"
	config.NSName = "ns1"
	config.Nameservers = ""
	if err := customdns.Configure("", config.Domain); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		config.Domain = oldDomain
		config.IP = oldIP
		config.NSName = oldNS
		config.Nameservers = oldNameservers
		_ = customdns.Configure("", oldDomain)
	})
}
func query(t *testing.T, name string, kind uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), kind)
	writer := &responseWriter{}
	handleQuery(writer, req)
	if writer.msg == nil {
		t.Fatal("missing response")
	}
	if _, err := writer.msg.Pack(); err != nil {
		t.Fatalf("invalid wire response: %v", err)
	}
	return writer.msg
}
func TestAuthoritativeProxyAddresses(t *testing.T) {
	setup(t)
	for _, host := range []string{"8.8.8.8.example.test", "8-8-8-8.example.test", "2001-4860-4860--8888.example.test", "ns1.example.test"} {
		msg := query(t, host, dns.TypeA)
		if !msg.Authoritative || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
			t.Fatalf("%s: %v", host, msg)
		}
		rr, ok := msg.Answer[0].(*dns.A)
		if !ok || rr.A.String() != config.IP {
			t.Fatalf("must return proxy IP: %v", msg)
		}
		msg = query(t, host, dns.TypeAAAA)
		if len(msg.Answer) != 0 || msg.Rcode != dns.RcodeSuccess || len(msg.Ns) != 1 {
			t.Fatalf("IPv4 proxy has AAAA: %v", msg)
		}
	}
	config.IP = "2001:db8::10"
	msg := query(t, "8.8.8.8.example.test", dns.TypeAAAA)
	if len(msg.Answer) != 1 || msg.Answer[0].(*dns.AAAA).AAAA.String() != config.IP {
		t.Fatalf("IPv6 proxy: %v", msg)
	}
	if msg = query(t, "8.8.8.8.example.test", dns.TypeA); len(msg.Answer) != 0 {
		t.Fatalf("IPv6 used as A: %v", msg)
	}
	ns := query(t, "example.test", dns.TypeNS)
	if len(ns.Answer) != 1 || len(ns.Extra) != 1 {
		t.Fatalf("NS glue: %v", ns)
	}
	if _, ok := ns.Extra[0].(*dns.AAAA); !ok {
		t.Fatalf("wrong NS glue family: %v", ns.Extra)
	}
}
func TestNegativeAndOutsideZone(t *testing.T) {
	setup(t)
	for _, name := range []string{"8.8.8.8.other.test", "8.8.8.8.evil-example.test", "example.test.evil"} {
		msg := query(t, name, dns.TypeA)
		if msg.Rcode != dns.RcodeRefused || msg.Authoritative || len(msg.Answer) != 0 {
			t.Fatalf("outside zone: %v", msg)
		}
	}
	msg := query(t, "missing.example.test", dns.TypeA)
	if msg.Rcode != dns.RcodeNameError || !msg.Authoritative || len(msg.Ns) != 1 {
		t.Fatalf("NXDOMAIN: %v", msg)
	}
	for _, kind := range []uint16{dns.TypeMX, dns.TypeCNAME, dns.TypeSRV, dns.TypeTXT} {
		msg = query(t, "8.8.8.8.example.test", kind)
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 || len(msg.Ns) != 1 {
			t.Fatalf("fabricated fallback: %v", msg)
		}
	}
	first := query(t, "example.test", dns.TypeSOA).Answer[0].(*dns.SOA).Serial
	second := query(t, "example.test", dns.TypeSOA).Answer[0].(*dns.SOA).Serial
	if first != second {
		t.Fatal("SOA serial varies between queries")
	}
}
func TestMalformedQueries(t *testing.T) {
	setup(t)
	for _, tc := range []struct {
		req  *dns.Msg
		code int
	}{
		{&dns.Msg{}, dns.RcodeFormatError},
		{&dns.Msg{Question: []dns.Question{{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, {Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}, dns.RcodeFormatError},
		{&dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate}}, dns.RcodeNotImplemented},
	} {
		w := &responseWriter{}
		handleQuery(w, tc.req)
		if w.msg == nil || w.msg.Rcode != tc.code {
			t.Fatalf("got %v want %d", w.msg, tc.code)
		}
	}
	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeA)
	req.SetEdns0(4096, false)
	req.IsEdns0().SetVersion(1)
	w := &responseWriter{}
	handleQuery(w, req)
	if w.msg.Rcode != dns.RcodeBadVers || w.msg.IsEdns0() == nil {
		t.Fatalf("BADVERS: %v", w.msg)
	}
	if _, err := w.msg.Pack(); err != nil {
		t.Fatal(err)
	}
}
func TestTXTCanonicalAndCustomCNAME(t *testing.T) {
	setup(t)
	name := "_acme-challenge.8.8.8.8.example.test"
	if err := txtstore.Put(strings.ToUpper(name), "challenge", 60); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { txtstore.Delete(name) })
	msg := query(t, name, dns.TypeTXT)
	if len(msg.Answer) != 1 || msg.Answer[0].(*dns.TXT).Txt[0] != "challenge" {
		t.Fatalf("TXT: %v", msg)
	}
	file := filepath.Join(t.TempDir(), "records")
	if err := os.WriteFile(file, []byte("alias.example.test CNAME destination.example.test.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := customdns.Configure(file, config.Domain); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeCNAME} {
		msg = query(t, "alias.example.test", kind)
		if len(msg.Answer) != 1 || msg.Answer[0].Header().Rrtype != dns.TypeCNAME {
			t.Fatalf("CNAME type %d: %v", kind, msg)
		}
	}
}
func TestUDPTruncation(t *testing.T) {
	setup(t)
	var records strings.Builder
	for i := 0; i < 20; i++ {
		records.WriteString("large.example.test TXT \"" + strings.Repeat("x", 200) + "\"\n")
	}
	file := filepath.Join(t.TempDir(), "records")
	if err := os.WriteFile(file, []byte(records.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := customdns.Configure(file, config.Domain); err != nil {
		t.Fatal(err)
	}
	req := new(dns.Msg)
	req.SetQuestion("large.example.test.", dns.TypeTXT)
	req.SetEdns0(65535, false)
	w := &responseWriter{}
	handleQuery(w, req)
	bytes, err := w.msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !w.msg.Truncated || len(bytes) > 1232 {
		t.Fatalf("UDP response not bounded: %d, TC=%v", len(bytes), w.msg.Truncated)
	}
}
func TestUDPAndTCPLifecycle(t *testing.T) {
	setup(t)
	tcp, udp := listenPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	ready := make(chan struct{})
	go func() { finished <- serveListenersReady(ctx, tcp, udp, ready) }()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatalf("server stopped before ready: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("DNS readiness timed out")
	}
	req := new(dns.Msg)
	req.SetQuestion("8.8.8.8.example.test.", dns.TypeA)
	for _, transport := range []string{"udp", "tcp"} {
		client := dns.Client{Net: transport, Timeout: 100 * time.Millisecond}
		deadline := time.Now().Add(3 * time.Second)
		for {
			reply, _, err := client.Exchange(req, tcp.Addr().String())
			if err == nil {
				if len(reply.Answer) != 1 {
					t.Fatalf("%s response: %v", transport, reply)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s server did not become ready: %v", transport, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("DNS did not shut down")
	}
}

func listenPair(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	var lastErr error
	// Windows can reserve different ephemeral port ranges for UDP and TCP.
	// Retry a new pair rather than assuming a TCP ephemeral port is free on UDP.
	for i := 0; i < 20; i++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err == nil {
			t.Cleanup(func() { tcp.Close(); udp.Close() })
			return tcp, udp
		}
		lastErr = err
		tcp.Close()
	}
	t.Fatalf("could not reserve a TCP/UDP port pair: %v", lastErr)
	return nil, nil
}

func TestReadinessIsNotReportedOnBindFailure(t *testing.T) {
	setup(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	oldListen, oldRecords := config.DNSListen, config.RecordsFile
	config.DNSListen, config.RecordsFile = listener.Addr().String(), ""
	t.Cleanup(func() { config.DNSListen, config.RecordsFile = oldListen, oldRecords })
	ready := make(chan struct{}, 1)
	if err := ServeReady(context.Background(), ready); err == nil {
		t.Fatal("expected bind failure")
	}
	select {
	case <-ready:
		t.Fatal("reported ready after bind failure")
	default:
	}
}

func TestCancellationBeforeReadyReceiver(t *testing.T) {
	setup(t)
	tcp, udp := listenPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	finished := make(chan error, 1)
	go func() { finished <- serveListenersReady(ctx, tcp, udp, ready) }()
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("unread readiness channel blocked cancellation")
	}
}

func TestCustomAddressesOverrideProxyAndNameserverGlue(t *testing.T) {
	setup(t)
	// A public nameserver may forward DNS to a private proxy. Explicit address
	// records must override the complete A/AAAA set, not leave a private fallback.
	config.IP = "fd00::10"
	path := filepath.Join(t.TempDir(), "records")
	data := "ns1.example.test A 192.0.2.53\n8.8.8.8.example.test A 8.8.8.8\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := customdns.Configure(path, config.Domain); err != nil {
		t.Fatal(err)
	}
	msg := query(t, "example.test", dns.TypeNS)
	if len(msg.Extra) != 1 || msg.Extra[0].(*dns.A).A.String() != "192.0.2.53" {
		t.Fatalf("incorrect public NS glue: %v", msg)
	}
	for _, name := range []string{"ns1.example.test", "8.8.8.8.example.test"} {
		msg = query(t, name, dns.TypeAAAA)
		if len(msg.Answer) != 0 || msg.Rcode != dns.RcodeSuccess {
			t.Fatalf("unexpected private proxy fallback: %v", msg)
		}
	}
	msg = query(t, "8.8.8.8.example.test", dns.TypeA)
	if len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != "8.8.8.8" {
		t.Fatalf("direct backend override: %v", msg)
	}
}
