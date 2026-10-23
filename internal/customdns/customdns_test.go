package customdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseRecords(t *testing.T) {
	text := `host.example.test A 192.0.2.10
host.example.test AAAA 2001:db8::10
host.example.test TXT "Hello  world"
alias.example.test CNAME host.example.test.
example.test MX mail.example.test.
`
	parsed, err := parse(strings.NewReader(text), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed["host.example.test."]) != 3 {
		t.Fatalf("records: %v", parsed)
	}
	txt := parsed["host.example.test."][2].(*dns.TXT)
	if strings.Join(txt.Txt, "") != "Hello  world" {
		t.Fatalf("TXT changed: %v", txt.Txt)
	}
	mx := parsed["example.test."][0].(*dns.MX)
	if mx.Preference != 10 {
		t.Fatalf("legacy MX preference: %d", mx.Preference)
	}
}
func TestRejectInvalidRecords(t *testing.T) {
	for _, line := range []string{
		"host.evil-example.test A 192.0.2.1",
		"host.example.test A 2001:db8::1",
		"host.example.test AAAA 192.0.2.1",
		"example.test CNAME other.example.test.",
		"host.example.test CNAME other.example.test.\nhost.example.test A 192.0.2.1",
		"host.example.test BOGUS nonsense",
		"host.example.test A",
	} {
		if _, err := parse(strings.NewReader(line), "example.test"); err == nil {
			t.Fatalf("accepted %q", line)
		}
	}
}
func TestConfigureIsAtomicAndRecordsAreCopies(t *testing.T) {
	t.Cleanup(func() { _ = Configure("", "example.test") })
	path := filepath.Join(t.TempDir(), "records.txt")
	if err := os.WriteFile(path, []byte("a.example.test AAAA 2001:db8::1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Configure(path, "example.test"); err != nil {
		t.Fatal(err)
	}
	got := Records("A.EXAMPLE.TEST", dns.TypeAAAA)
	if len(got) != 1 {
		t.Fatalf("AAAA missing: %v", got)
	}
	got[0].Header().Name = "corrupted."
	if Records("a.example.test", dns.TypeAAAA)[0].Header().Name != "a.example.test." {
		t.Fatal("shared record mutated")
	}
	if !Exists("example.test") {
		t.Fatal("empty nonterminal missing")
	}
	if err := os.WriteFile(path, []byte("outside.invalid A 192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Configure(path, "example.test"); err == nil {
		t.Fatal("expected invalid zone")
	}
	if len(Records("a.example.test", dns.TypeAAAA)) != 1 {
		t.Fatal("bad load replaced valid config")
	}
}
