package resolver

import "testing"

func TestParseHost(t *testing.T) {
	cases := []struct{ host, want string }{
		{"1.2.3.4.example.test", "1.2.3.4"},
		{"1-2-3-4.example.test", "1.2.3.4"},
		{"2001-DB8--1.EXAMPLE.TEST.", "2001:db8::1"},
		{"fd00--123.example.test", "fd00::123"},
		{"1.2.3.4.evil-example.test", ""},
		{"1.2.3.4.example.test.evil", ""},
		{"1.2.3.4.extra.example.test", ""},
		{"256.2.3.4.example.test", ""},
		{"01.2.3.4.example.test", ""},
		{"1-2-3-4.example.test:443", ""},
		{"example.test", ""},
		{"1.2.3.4..example.test", ""},
		{"1-2-3-4\\046example.test", ""},
		{"http://1-2-3-4.example.test", ""},
		{"2001-db8-1.example.test", ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got, err := ParseHost(tc.host, "example.test")
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted %s as %s", tc.host, got)
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("got %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}
func TestParseIPv6RejectsIPv4(t *testing.T) {
	if got := ParseIPv6("1-2-3-4.example.test"); got != nil {
		t.Fatalf("IPv4 treated as IPv6: %v", got)
	}
}
