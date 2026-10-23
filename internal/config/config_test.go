package config

import (
	"net"
	"testing"
)

func configure(t *testing.T, extra ...string) {
	t.Helper()
	args := []string{"--domain=Example.Test.", "--ip=192.168.1.2"}
	if err := Load(append(args, extra...)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndHostPolicy(t *testing.T) {
	configure(t)
	if Domain != "example.test" || NSName != "ns1" {
		t.Fatal("defaults/canonicalization failed")
	}
	for _, name := range []string{"8.8.8.8.example.test", "8-8-8-8.EXAMPLE.TEST.", "2606-4700-4700--1111.example.test"} {
		if _, err := ValidateHostname(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"", "../../etc/passwd", "8.8.8.8.evil.test", "8.8.8.8.notexample.test",
		"10.0.0.1.example.test", "127.0.0.1.example.test", "169.254.169.254.example.test",
		"100.64.1.2.example.test", "0.0.0.0.example.test", "224.0.0.1.example.test", "example.test"} {
		if _, err := ValidateHostname(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	configure(t, "--allowed-cidrs=192.168.1.0/24,fd00::/8")
	if _, err := ValidateHostname("192-168-1-5.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateHostname("fd00--1.example.test"); err != nil {
		t.Fatal(err)
	}
	if TargetAllowed(net.ParseIP("8.8.8.8")) {
		t.Fatal("explicit allowlist allowed public address")
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, arg := range []string{"--domain=../etc", "--domain=bad..example", "--ip=hostname", "--ip=0.0.0.0",
		"--ns=ns.other", "--api-listen=0.0.0.0:80", "--dns-listen=:0", "--https-listen=host:443",
		"--upstream-port=65536", "--tls-mode=unknown", "--allowed-cidrs=10.0.0.1", "--acme-directory=http://insecure.test",
		"--acme-email=not-email", "--data-dir=", "--acme-dns-timeout=0s"} {
		if err := Load([]string{"--domain=example.test", "--ip=192.168.1.2", arg}); err == nil {
			t.Errorf("accepted %s", arg)
		}
	}
	if err := Load([]string{"--version"}); err != nil || !ShowVersion {
		t.Fatal("version requires config", err)
	}
}

func TestEnvironmentAndFlagPrecedence(t *testing.T) {
	t.Setenv("DNSBOX_DOMAIN", "env.test")
	t.Setenv("DNSBOX_IP", "192.168.1.2")
	t.Setenv("DNSBOX_API_LISTEN", "")
	if err := Load([]string{"--domain=flag.test"}); err != nil {
		t.Fatal(err)
	}
	if Domain != "flag.test" || APIListen != "" {
		t.Fatal("incorrect precedence")
	}
	t.Setenv("DNSBOX_DEBUG", "invalid")
	t.Setenv("DNSBOX_UPSTREAM_PORT", "invalid")
	t.Setenv("DNSBOX_ACME_DNS_TIMEOUT", "invalid")
	if err := Load([]string{"--domain=flag.test", "--debug=false", "--upstream-port=80", "--acme-dns-timeout=2m"}); err != nil {
		t.Fatal("valid flags must override invalid environment defaults", err)
	}
}
