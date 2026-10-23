package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestNameserversDefaultAndCanonicalRoster(t *testing.T) {
	configure(t)
	if got := AuthoritativeNameservers(); !reflect.DeepEqual(got, []Nameserver{{Name: "ns1.example.test", IP: "192.168.1.2"}}) {
		t.Fatalf("default nameserver: %v", got)
	}
	roster := " NS3 = 2001:0db8::53 , NS1=::ffff:192.168.1.2,ns2=192.0.2.53"
	configure(t, "--nameservers="+roster)
	want := []Nameserver{
		{Name: "ns1.example.test", IP: "192.168.1.2"},
		{Name: "ns2.example.test", IP: "192.0.2.53"},
		{Name: "ns3.example.test", IP: "2001:db8::53"},
	}
	if got := AuthoritativeNameservers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical roster: %v, want %v", got, want)
	}
	copy := AuthoritativeNameservers()
	copy[0].Name = "changed.example.test"
	if !reflect.DeepEqual(AuthoritativeNameservers(), want) {
		t.Fatal("caller can modify validated roster")
	}
	configure(t, "--ns=NS3", "--ip=2001:db8::53", "--nameservers=ns2=192.0.2.53,ns3=2001:db8::53,ns1=192.168.1.2")
	if got := AuthoritativeNameservers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("roster depends on local server or input order: %v", got)
	}
	configure(t)
	if len(AuthoritativeNameservers()) != 1 {
		t.Fatal("previous cluster roster survived reconfiguration")
	}
}

func TestInvalidNameserverRosters(t *testing.T) {
	for _, roster := range []string{
		"ns2=192.0.2.53",
		"ns1=192.0.2.53",
		"ns1=192.168.1.2,NS1=192.168.1.2",
		"ns1=192.168.1.2,",
		" ns1=192.168.1.2, ",
		"ns1=192.168.1.2,ns2",
		"ns1=192.168.1.2,=192.0.2.53",
		"ns1=192.168.1.2,ns2.other=192.0.2.53",
		"ns1=192.168.1.2,-ns2=192.0.2.53",
		"ns1=192.168.1.2,ns2_=192.0.2.53",
		"ns1=192.168.1.2," + strings.Repeat("x", 64) + "=192.0.2.53",
		"ns1=192.168.1.2,ns2=hostname",
		"ns1=192.168.1.2,ns2=192.0.2.53:53",
		"ns1=192.168.1.2,ns2=0.0.0.0",
		"ns1=192.168.1.2,ns2=::",
		"ns1=192.168.1.2,ns2=224.0.0.1",
		"ns1=192.168.1.2,ns2=ff02::1",
		"ns1=192.168.1.2,ns2=255.255.255.255",
		"ns1=192.168.1.2,ns2=169.254.1.1",
		"ns1=192.168.1.2,ns2=fe80::1",
		"ns1=192.168.1.2,ns2=fe80::1%eth0",
		"ns1=192.168.1.2,ns2=::ffff:0.0.0.0",
		"ns1=192.168.1.2,ns2=::ffff:224.0.0.1",
	} {
		t.Run(roster, func(t *testing.T) {
			if err := Load([]string{"--domain=example.test", "--ip=192.168.1.2", "--nameservers=" + roster}); err == nil {
				t.Fatalf("accepted invalid roster %q", roster)
			}
		})
	}
	zone := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 59)
	if err := Load([]string{"--domain=" + zone, "--ip=192.168.1.2"}); err == nil {
		t.Fatal("accepted nameserver hostname exceeding DNS limits")
	}
}

func TestNameserversAndClusterFileEnvironment(t *testing.T) {
	t.Setenv("DNSBOX_NAMESERVERS", "ns1=192.168.1.2,ns2=192.0.2.53")
	t.Setenv("DNSBOX_CLUSTER_FILE", "env-cluster.json")
	configure(t)
	if len(AuthoritativeNameservers()) != 2 || ClusterFile != "env-cluster.json" {
		t.Fatalf("environment not loaded: %v, %s", AuthoritativeNameservers(), ClusterFile)
	}
	configure(t, "--nameservers=", "--cluster-file=explicit-cluster.json")
	if len(AuthoritativeNameservers()) != 1 || ClusterFile != "explicit-cluster.json" {
		t.Fatal("explicit flags did not override environment")
	}
	configure(t, "--nameservers=ns1=192.168.1.2,local=127.0.0.1,private=fd00::53", "--cluster-file=")
	if len(AuthoritativeNameservers()) != 3 || ClusterFile != "" {
		t.Fatal("private network roster or empty cluster override rejected")
	}
}
