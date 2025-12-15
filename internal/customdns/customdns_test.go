package customdns

import (
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func TestMatch(t *testing.T) {
	// Reset records for testing
	once = sync.Once{}
	records = []Record{}

	// Manually add test records
	records = []Record{
		{Type: "A", Name: "test.example.com", Data: "192.168.1.1"},
		{Type: "A", Name: "test.example.com", Data: "192.168.1.2"},
		{Type: "TXT", Name: "test.example.com", Data: "test-value"},
		{Type: "CNAME", Name: "alias.example.com", Data: "target.example.com"},
		{Type: "MX", Name: "mail.example.com", Data: "mail.example.com"},
		{Type: "A", Name: "other.example.com", Data: "10.0.0.1"},
	}

	tests := []struct {
		name     string
		qname    string
		qtype    uint16
		expected int // number of expected matches
	}{
		{
			name:     "A record match",
			qname:    "test.example.com",
			qtype:    dns.TypeA,
			expected: 2, // Two A records
		},
		{
			name:     "TXT record match",
			qname:    "test.example.com",
			qtype:    dns.TypeTXT,
			expected: 1,
		},
		{
			name:     "CNAME record match",
			qname:    "alias.example.com",
			qtype:    dns.TypeCNAME,
			expected: 1,
		},
		{
			name:     "MX record match",
			qname:    "mail.example.com",
			qtype:    dns.TypeMX,
			expected: 1,
		},
		{
			name:     "No match - wrong type",
			qname:    "test.example.com",
			qtype:    dns.TypeAAAA,
			expected: 0,
		},
		{
			name:     "No match - wrong name",
			qname:    "nonexistent.example.com",
			qtype:    dns.TypeA,
			expected: 0,
		},
		{
			name:     "Case insensitive match",
			qname:    "TEST.EXAMPLE.COM",
			qtype:    dns.TypeA,
			expected: 2,
		},
		{
			name:     "FQDN with trailing dot",
			qname:    "test.example.com.",
			qtype:    dns.TypeA,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Match(tt.qname, tt.qtype)
			if len(result) != tt.expected {
				t.Errorf("Match(%q, %d) returned %d records, want %d", tt.qname, tt.qtype, len(result), tt.expected)
			}

			// Verify record types match
			for _, r := range result {
				switch tt.qtype {
				case dns.TypeA:
					if r.Type != "A" {
						t.Errorf("Match returned record with type %q, want A", r.Type)
					}
				case dns.TypeTXT:
					if r.Type != "TXT" {
						t.Errorf("Match returned record with type %q, want TXT", r.Type)
					}
				case dns.TypeCNAME:
					if r.Type != "CNAME" {
						t.Errorf("Match returned record with type %q, want CNAME", r.Type)
					}
				case dns.TypeMX:
					if r.Type != "MX" {
						t.Errorf("Match returned record with type %q, want MX", r.Type)
					}
				}
			}
		})
	}
}

func TestMatchWithEmbeddedFile(t *testing.T) {
	// Reset to test loading from embedded file
	once = sync.Once{}
	records = []Record{}

	// Load from embedded file
	Load()

	// Test that we can match records from the embedded file
	// Note: This depends on the actual content of custom_domains.txt
	// We'll test that Load() works and Match() doesn't crash
	result := Match("dnsbox.io", dns.TypeCNAME)
	// We don't know the exact count, but it should not crash
	_ = result
}

func TestLoadIdempotent(t *testing.T) {
	// Reset
	once = sync.Once{}
	records = []Record{}

	// First load
	Load()
	firstCount := len(records)

	// Second load should not add more records
	Load()
	secondCount := len(records)

	if firstCount != secondCount {
		t.Errorf("Load() not idempotent: first load had %d records, second had %d", firstCount, secondCount)
	}
}

func TestMatchEmptyStore(t *testing.T) {
	// Reset
	once = sync.Once{}
	records = []Record{}

	result := Match("any.example.com", dns.TypeA)
	if len(result) != 0 {
		t.Errorf("Match() on empty store returned %d records, want 0", len(result))
	}
}

func BenchmarkMatch(t *testing.B) {
	// Reset and set up
	once = sync.Once{}
	records = []Record{
		{Type: "A", Name: "test.example.com", Data: "192.168.1.1"},
		{Type: "A", Name: "test.example.com", Data: "192.168.1.2"},
		{Type: "TXT", Name: "test.example.com", Data: "test-value"},
	}

	for i := 0; i < t.N; i++ {
		_ = Match("test.example.com", dns.TypeA)
	}
}

