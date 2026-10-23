package customdns

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func configureAliasTest(t *testing.T, contents string) {
	t.Helper()
	lookup, now := aliasLookupIP, aliasNow
	t.Cleanup(func() {
		aliasLookupIP, aliasNow = lookup, now
		_ = Configure("", "example.test")
	})
	path := filepath.Join(t.TempDir(), "records.txt")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Configure(path, "example.test"); err != nil {
		t.Fatal(err)
	}
}

func TestAliasParsingAndCoexistence(t *testing.T) {
	parsed, targets, err := parseConfig(strings.NewReader(`example.test ALIAS Edge.Provider.TEST.
example.test TXT "verification=value with spaces"
example.test MX 10 mail.provider.test.
`), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if targets["example.test."] != "edge.provider.test." {
		t.Fatalf("unexpected target: %v", targets)
	}
	if len(parsed["example.test."]) != 2 {
		t.Fatalf("ALIAS should not create a wire CNAME: %v", parsed)
	}
	if txt := parsed["example.test."][0].(*dns.TXT); txt.Txt[0] != "verification=value with spaces" {
		t.Fatalf("changed TXT: %v", txt)
	}
}

func TestRejectUnsafeAliases(t *testing.T) {
	for _, text := range []string{
		"host.example.test ALIAS edge.provider.test.",
		"example.test ALIAS example.test.",
		"example.test ALIAS child.example.test.",
		"example.test ALIAS *.provider.test.",
		"example.test ALIAS 192.0.2.1",
		"example.test ALIAS 2001:db8::1",
		"example.test ALIAS [2001:db8::1]",
		"example.test ALIAS https://provider.test",
		"example.test ALIAS edge..provider.test",
		"example.test ALIAS -edge.provider.test",
		"example.test ALIAS edge-.provider.test",
		"example.test ALIAS edge_provider.test",
		"example.test ALIAS provider",
		"example.test ALIAS first.provider.test second.provider.test",
		"example.test ALIAS first.provider.test\nexample.test ALIAS second.provider.test",
		"example.test ALIAS edge.provider.test\nexample.test A 192.0.2.1",
		"example.test A 192.0.2.1\nexample.test ALIAS edge.provider.test",
		"example.test ALIAS edge.provider.test\nexample.test AAAA 2001:db8::1",
		"example.test AAAA 2001:db8::1\nexample.test ALIAS edge.provider.test",
		"example.test ALIAS edge.provider.test\nexample.test CNAME edge.provider.test",
	} {
		t.Run(strings.ReplaceAll(text, "\n", ";"), func(t *testing.T) {
			if _, _, err := parseConfig(strings.NewReader(text), "example.test"); err == nil {
				t.Fatalf("accepted invalid ALIAS: %s", text)
			}
		})
	}
}

func TestAliasInitialFailureIsReported(t *testing.T) {
	configureAliasTest(t, "example.test ALIAS edge.provider.test.\nexample.test TXT \"verification=keep\"\n")
	failure := errors.New("resolver unavailable")
	aliasLookupIP = func(ctx context.Context, target string) ([]net.IPAddr, error) {
		if target != "edge.provider.test." {
			t.Fatalf("looked up unconfigured target: %q", target)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) < 4*time.Second {
			t.Fatal("lookup must have a five-second upper bound")
		}
		return nil, failure
	}
	if err := RefreshAliases(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("initial failure lost: %v", err)
	}
	if !AliasUnavailable("EXAMPLE.TEST") || !Exists("example.test") {
		t.Fatal("failed alias must exist but remain unavailable")
	}
	if len(Records("example.test", dns.TypeA)) != 0 || len(Records("example.test", dns.TypeAAAA)) != 0 {
		t.Fatal("failed initial lookup created addresses")
	}
	if txt := Records("example.test", dns.TypeTXT); len(txt) != 1 || txt[0].(*dns.TXT).Txt[0] != "verification=keep" {
		t.Fatalf("TXT must survive ALIAS failure: %v", txt)
	}
}

func TestAliasRotationRetentionAndExpiry(t *testing.T) {
	configureAliasTest(t, "example.test ALIAS edge.provider.test.\nexample.test TXT \"verification=keep\"\n")
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	aliasNow = func() time.Time { return now }
	calls := 0
	fail := false
	aliasLookupIP = func(ctx context.Context, target string) ([]net.IPAddr, error) {
		calls++
		if fail {
			return nil, errors.New("temporary DNS outage")
		}
		if calls == 1 {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}, {IP: net.ParseIP("192.0.2.10")}, {IP: net.ParseIP("2001:db8::10")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.20")}}, nil
	}
	if err := RefreshAliases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if AliasUnavailable("example.test") {
		t.Fatal("fresh alias unavailable")
	}
	a := Records("example.test", dns.TypeA)
	if len(a) != 1 || !a[0].(*dns.A).A.Equal(net.ParseIP("192.0.2.10")) || a[0].Header().Ttl != 60 {
		t.Fatalf("unexpected initial A response: %v", a)
	}
	if aaaa := Records("example.test", dns.TypeAAAA); len(aaaa) != 1 {
		t.Fatalf("missing initial AAAA: %v", aaaa)
	}
	a[0].(*dns.A).A[0] = 1
	if !Records("example.test", dns.TypeA)[0].(*dns.A).A.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatal("response mutation corrupted ALIAS cache")
	}
	now = now.Add(time.Minute)
	if err := RefreshAliases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := Records("example.test", dns.TypeA); len(got) != 1 || !got[0].(*dns.A).A.Equal(net.ParseIP("192.0.2.20")) {
		t.Fatalf("rotation did not replace A record: %v", got)
	}
	if got := Records("example.test", dns.TypeAAAA); len(got) != 0 {
		t.Fatalf("rotation retained removed IPv6 address: %v", got)
	}
	fail = true
	now = now.Add(59*time.Minute + 40*time.Second)
	if err := RefreshAliases(context.Background()); err == nil {
		t.Fatal("refresh failure must be reported")
	}
	if got := Records("example.test", dns.TypeA); len(got) != 1 || got[0].Header().Ttl != 20 {
		t.Fatalf("fresh cache not retained with bounded TTL: %v", got)
	}
	if AliasUnavailable("example.test") {
		t.Fatal("cache marked stale too early")
	}
	now = now.Add(20 * time.Second)
	if !AliasUnavailable("example.test") || len(Records("example.test", dns.TypeA)) != 0 {
		t.Fatal("expired addresses must never be served")
	}
	if len(Records("example.test", dns.TypeTXT)) != 1 {
		t.Fatal("alias expiry removed independent TXT record")
	}
	if calls != 3 {
		t.Fatalf("query path performed a lookup; calls=%d", calls)
	}
}

func TestAliasRejectsEmptyOrUnusableResolution(t *testing.T) {
	configureAliasTest(t, "example.test ALIAS edge.provider.test.\n")
	for _, addresses := range [][]net.IPAddr{
		nil,
		{{IP: net.ParseIP("0.0.0.0")}, {IP: net.ParseIP("224.0.0.1")}, {IP: net.ParseIP("::")}, {IP: net.ParseIP("::1")}},
	} {
		aliasLookupIP = func(context.Context, string) ([]net.IPAddr, error) { return addresses, nil }
		if err := RefreshAliases(context.Background()); err == nil || !AliasUnavailable("example.test") {
			t.Fatal("empty/unusable resolution must fail initial readiness")
		}
	}
}

func TestAliasRespectsCancellation(t *testing.T) {
	configureAliasTest(t, "example.test ALIAS edge.provider.test.\n")
	aliasLookupIP = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RefreshAliases(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
	done := make(chan struct{})
	go func() { RunAliasRefresh(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background refresher did not stop")
	}
}

func TestAliasReconfigureDiscardsInflightResult(t *testing.T) {
	configureAliasTest(t, "example.test ALIAS edge.provider.test.\n")
	started, proceed := make(chan struct{}), make(chan struct{})
	aliasLookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		close(started)
		<-proceed
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
	}
	done := make(chan error, 1)
	go func() { done <- RefreshAliases(context.Background()) }()
	<-started
	if err := Configure("", "example.test"); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if Exists("example.test") || len(Records("example.test", dns.TypeA)) != 0 || AliasUnavailable("example.test") {
		t.Fatal("old result was installed after reconfiguration")
	}
}
