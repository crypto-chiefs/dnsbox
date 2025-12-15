package resolver

import (
	"net"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected net.IP
		wantNil  bool
	}{
		{
			name:     "dash format with domain",
			input:    "1-2-3-4.dnsbox.io",
			expected: net.ParseIP("1.2.3.4"),
			wantNil:  false,
		},
		{
			name:     "dash format with trailing dot",
			input:    "1-2-3-4.dnsbox.io.",
			expected: net.ParseIP("1.2.3.4"),
			wantNil:  false,
		},
		{
			name:     "dot format with domain",
			input:    "1.2.3.4.dnsbox.io",
			expected: net.ParseIP("1.2.3.4"),
			wantNil:  false,
		},
		{
			name:     "dot format with trailing dot",
			input:    "1.2.3.4.dnsbox.io.",
			expected: net.ParseIP("1.2.3.4"),
			wantNil:  false,
		},
		{
			name:     "valid IP with multiple domain parts",
			input:    "192.168.1.1.example.dnsbox.io",
			expected: net.ParseIP("192.168.1.1"),
			wantNil:  false,
		},
		{
			name:     "invalid dash format - too few dashes",
			input:    "1-2-3.dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "invalid dash format - too many dashes",
			input:    "1-2-3-4-5.dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "invalid IP address",
			input:    "999.999.999.999.dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "too few parts",
			input:    "1.2.dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "just domain name",
			input:    "dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "private IP range",
			input:    "10-0-0-1.dnsbox.io",
			expected: net.ParseIP("10.0.0.1"),
			wantNil:  false,
		},
		{
			name:     "localhost",
			input:    "127-0-0-1.dnsbox.io",
			expected: net.ParseIP("127.0.0.1"),
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIPv4(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("ParseIPv4(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("ParseIPv4(%q) = nil, want %v", tt.input, tt.expected)
					return
				}
				if !result.Equal(tt.expected) {
					t.Errorf("ParseIPv4(%q) = %v, want %v", tt.input, result, tt.expected)
				}
				// Ensure it's IPv4
				if result.To4() == nil {
					t.Errorf("ParseIPv4(%q) returned non-IPv4 address: %v", tt.input, result)
				}
			}
		})
	}
}

func TestParseIPv6(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected net.IP
		wantNil  bool
	}{
		{
			name:     "IPv6 with double dash (compressed)",
			input:    "2a01-4f8-c17-b8f--1.dnsbox.io",
			expected: net.ParseIP("2a01:4f8:c17:b8f::1"),
			wantNil:  false,
		},
		{
			name:     "IPv6 with double dash and trailing dot",
			input:    "2001-0db8--1.dnsbox.io.",
			expected: net.ParseIP("2001:db8::1"),
			wantNil:  false,
		},
		{
			name:     "full IPv6 address",
			input:    "2001-0db8-85a3-0000-0000-8a2e-0370-7334.dnsbox.io",
			expected: net.ParseIP("2001:db8:85a3:0:0:8a2e:370:7334"),
			wantNil:  false,
		},
		{
			name:     "IPv6 localhost",
			input:    "--1.dnsbox.io",
			expected: net.ParseIP("::1"),
			wantNil:  false,
		},
		{
			name:     "IPv6 with multiple colons",
			input:    "fe80--1.dnsbox.io",
			expected: net.ParseIP("fe80::1"),
			wantNil:  false,
		},
		{
			name:     "invalid IPv6 format",
			input:    "invalid-ipv6.dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "just domain name",
			input:    "dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
		{
			name:     "IPv4 in IPv6 test (should fail)",
			input:    "1-2-3-4.dnsbox.io",
			expected: nil,
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIPv6(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("ParseIPv6(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("ParseIPv6(%q) = nil, want %v", tt.input, tt.expected)
					return
				}
				if !result.Equal(tt.expected) {
					t.Errorf("ParseIPv6(%q) = %v, want %v", tt.input, result, tt.expected)
				}
				// Ensure it's IPv6
				if result.To16() == nil {
					t.Errorf("ParseIPv6(%q) returned non-IPv6 address: %v", tt.input, result)
				}
			}
		})
	}
}

func TestParseIPv4EdgeCases(t *testing.T) {
	// Test boundary values
	edgeCases := []struct {
		name  string
		input string
		valid bool
	}{
		{"minimum valid IP", "0-0-0-0.dnsbox.io", true},
		{"maximum valid IP", "255-255-255-255.dnsbox.io", true},
		{"out of range octet", "256-1-1-1.dnsbox.io", false},
		{"negative number", "-1-2-3-4.dnsbox.io", false},
		{"non-numeric", "a-b-c-d.dnsbox.io", false},
		{"mixed format", "1.2-3-4.dnsbox.io", false},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIPv4(tc.input)
			if tc.valid && result == nil {
				t.Errorf("Expected valid IP for %q but got nil", tc.input)
			}
			if !tc.valid && result != nil {
				t.Errorf("Expected nil for invalid input %q but got %v", tc.input, result)
			}
		})
	}
}

func BenchmarkParseIPv4(t *testing.B) {
	inputs := []string{
		"1-2-3-4.dnsbox.io",
		"192.168.1.1.dnsbox.io",
		"10-0-0-1.dnsbox.io",
	}

	for i := 0; i < t.N; i++ {
		for _, input := range inputs {
			_ = ParseIPv4(input)
		}
	}
}

func BenchmarkParseIPv6(t *testing.B) {
	inputs := []string{
		"2a01-4f8-c17-b8f--1.dnsbox.io",
		"2001-0db8--1.dnsbox.io",
		"--1.dnsbox.io",
	}

	for i := 0; i < t.N; i++ {
		for _, input := range inputs {
			_ = ParseIPv6(input)
		}
	}
}

