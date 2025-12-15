package blacklist

import (
	"net"
	"testing"
)

func TestIsBlocked(t *testing.T) {
	// Reset loaded state for testing
	loaded = false
	exactIPs = make(map[string]struct{})
	cidrBlocks = []*net.IPNet{}

	// Load the embedded blacklist
	LoadEmbedded()

	// Test cases based on actual blacklist entries
	tests := []struct {
		name     string
		ip       string
		blocked  bool
		skipIfNo bool // Skip if blacklist is empty
	}{
		{
			name:     "invalid IP should not be blocked",
			ip:       "invalid-ip",
			blocked:  false,
			skipIfNo: false,
		},
		{
			name:     "empty string should not be blocked",
			ip:       "",
			blocked:  false,
			skipIfNo: false,
		},
		{
			name:     "random IP not in blacklist",
			ip:       "8.8.8.8",
			blocked:  false,
			skipIfNo: true, // Only test if blacklist has entries
		},
		{
			name:     "localhost should not be blocked",
			ip:       "127.0.0.1",
			blocked:  false,
			skipIfNo: false,
		},
		{
			name:     "private IP should not be blocked",
			ip:       "192.168.1.1",
			blocked:  false,
			skipIfNo: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipIfNo && len(exactIPs) == 0 && len(cidrBlocks) == 0 {
				t.Skip("Blacklist is empty, skipping test")
			}

			result := IsBlocked(tt.ip)
			if result != tt.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tt.ip, result, tt.blocked)
			}
		})
	}
}

func TestIsBlockedWithCIDR(t *testing.T) {
	// Reset loaded state for testing
	loaded = false
	exactIPs = make(map[string]struct{})
	cidrBlocks = []*net.IPNet{}

	// Manually add test entries
	_, cidr1, _ := net.ParseCIDR("192.168.100.0/24")
	cidrBlocks = append(cidrBlocks, cidr1)

	exactIPs["10.0.0.1"] = struct{}{}
	loaded = true

	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{
			name:    "IP in CIDR range should be blocked",
			ip:      "192.168.100.50",
			blocked: true,
		},
		{
			name:    "IP outside CIDR range should not be blocked",
			ip:      "192.168.101.50",
			blocked: false,
		},
		{
			name:    "Exact IP match should be blocked",
			ip:      "10.0.0.1",
			blocked: true,
		},
		{
			name:    "Similar IP should not be blocked",
			ip:      "10.0.0.2",
			blocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBlocked(tt.ip)
			if result != tt.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tt.ip, result, tt.blocked)
			}
		})
	}
}

func TestIsBlockedIPv6(t *testing.T) {
	// Reset loaded state for testing
	loaded = false
	exactIPs = make(map[string]struct{})
	cidrBlocks = []*net.IPNet{}

	// Manually add IPv6 test entries
	exactIPs["2001:db8::1"] = struct{}{}
	_, cidr1, _ := net.ParseCIDR("2001:db8::/32")
	cidrBlocks = append(cidrBlocks, cidr1)
	loaded = true

	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{
			name:    "IPv6 exact match should be blocked",
			ip:      "2001:db8::1",
			blocked: true,
		},
		{
			name:    "IPv6 in CIDR range should be blocked",
			ip:      "2001:db8::2",
			blocked: true,
		},
		{
			name:    "IPv6 outside range should not be blocked",
			ip:      "2001:db9::1",
			blocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBlocked(tt.ip)
			if result != tt.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tt.ip, result, tt.blocked)
			}
		})
	}
}

func TestLoadEmbedded(t *testing.T) {
	// Reset state
	loaded = false
	exactIPs = make(map[string]struct{})
	cidrBlocks = []*net.IPNet{}

	// First load
	LoadEmbedded()
	firstCount := len(exactIPs)
	firstCIDRCount := len(cidrBlocks)

	// Second load should be idempotent
	LoadEmbedded()
	secondCount := len(exactIPs)
	secondCIDRCount := len(cidrBlocks)

	if firstCount != secondCount {
		t.Errorf("LoadEmbedded() not idempotent: first load had %d IPs, second had %d", firstCount, secondCount)
	}

	if firstCIDRCount != secondCIDRCount {
		t.Errorf("LoadEmbedded() not idempotent: first load had %d CIDRs, second had %d", firstCIDRCount, secondCIDRCount)
	}

	if !loaded {
		t.Error("LoadEmbedded() should set loaded to true")
	}
}

func BenchmarkIsBlocked(t *testing.B) {
	// Reset and load
	loaded = false
	exactIPs = make(map[string]struct{})
	cidrBlocks = []*net.IPNet{}
	LoadEmbedded()

	testIPs := []string{
		"8.8.8.8",
		"192.168.1.1",
		"127.0.0.1",
		"10.0.0.1",
		"2001:db8::1",
	}

	for i := 0; i < t.N; i++ {
		for _, ip := range testIPs {
			_ = IsBlocked(ip)
		}
	}
}

