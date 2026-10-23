// Package config loads configuration before starting any services.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/crypto-chiefs/dnsbox/internal/blacklist"
	"github.com/crypto-chiefs/dnsbox/internal/resolver"
)

// Configuration is immutable after Load returns and services start.
var (
	Domain, IP, NSName                                      string
	Nameservers, ClusterFile                                string
	Debug, ShowVersion, CheckConfig                         bool
	DNSListen, HTTPSListen, APIListen, APIToken             string
	DataDir, TLSMode, ACMEEmail, ACMEDirectory, RecordsFile string
	AllowedCIDRs, IssueHostname                             string
	UpstreamPort                                            int
	ACMEDNSTimeout                                          time.Duration
	allowedNetworks                                         []netip.Prefix
)

func env(name, fallback string) string {
	if value, ok := os.LookupEnv("DNSBOX_" + name); ok {
		return value
	}
	return fallback
}

func defaultDataDir() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/dnsbox"
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "dnsbox")
	}
	return "dnsbox-data"
}

func Load(args []string) error {
	f := flag.NewFlagSet("dnsboxd", flag.ContinueOnError)
	f.StringVar(&Domain, "domain", env("DOMAIN", ""), "owned DNS zone, or home.arpa in local mode")
	f.StringVar(&IP, "ip", env("IP", ""), "DNSBox address advertised in DNS answers")
	f.StringVar(&NSName, "ns", env("NS_NAME", "ns1"), "nameserver label within the zone")
	f.StringVar(&Nameservers, "nameservers", env("NAMESERVERS", ""), "comma-separated authoritative nameservers as label=IP")
	f.StringVar(&ClusterFile, "cluster-file", env("CLUSTER_FILE", ""), "optional authenticated cluster configuration file")
	f.StringVar(&DNSListen, "dns-listen", env("DNS_LISTEN", ":53"), "UDP and TCP DNS bind address")
	f.StringVar(&HTTPSListen, "https-listen", env("HTTPS_LISTEN", ":443"), "HTTPS bind address")
	f.StringVar(&APIListen, "api-listen", env("API_LISTEN", "127.0.0.1:8080"), "loopback management bind address; empty disables")
	f.StringVar(&APIToken, "api-token", env("API_TOKEN", ""), "management bearer token; empty disables mutations")
	f.StringVar(&DataDir, "data-dir", env("DATA_DIR", defaultDataDir()), "persistent private certificate directory")
	f.StringVar(&TLSMode, "tls-mode", env("TLS_MODE", "acme"), "acme or local")
	f.StringVar(&ACMEEmail, "acme-email", env("ACME_EMAIL", ""), "ACME account contact email")
	f.StringVar(&ACMEDirectory, "acme-directory", env("ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"), "ACME directory URL")
	f.StringVar(&RecordsFile, "records-file", env("RECORDS_FILE", ""), "optional custom DNS records file")
	f.StringVar(&AllowedCIDRs, "allowed-cidrs", env("ALLOWED_CIDRS", ""), "restrict backends to these comma-separated CIDRs; empty allows public IPs")
	f.StringVar(&IssueHostname, "issue", "", "issue/export one certificate while serving DNS, then exit")
	port, portErr := strconv.Atoi(env("UPSTREAM_PORT", "80"))
	f.IntVar(&UpstreamPort, "upstream-port", port, "HTTP backend port")
	duration, durationErr := time.ParseDuration(env("ACME_DNS_TIMEOUT", "2m"))
	f.DurationVar(&ACMEDNSTimeout, "acme-dns-timeout", duration, "DNS propagation wait")
	debug, debugErr := strconv.ParseBool(env("DEBUG", "false"))
	f.BoolVar(&Debug, "debug", debug, "enable debug logs")
	f.BoolVar(&ShowVersion, "version", false, "show version and exit")
	f.BoolVar(&CheckConfig, "check-config", false, "validate configuration and exit")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(f.Args(), " "))
	}
	if ShowVersion {
		return nil
	}
	supplied := map[string]bool{}
	f.Visit(func(value *flag.Flag) { supplied[value.Name] = true })
	if (portErr != nil && !supplied["upstream-port"]) || (durationErr != nil && !supplied["acme-dns-timeout"]) || (debugErr != nil && !supplied["debug"]) {
		return errors.New("invalid DNSBOX_UPSTREAM_PORT, DNSBOX_ACME_DNS_TIMEOUT, or DNSBOX_DEBUG")
	}
	return Validate()
}

func validDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func Validate() error {
	Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(Domain)), ".")
	if !validDNSName(Domain) || !strings.Contains(Domain, ".") {
		return errors.New("--domain must be a valid DNS zone")
	}
	NSName = strings.ToLower(NSName)
	if !validDNSName(NSName) || strings.Contains(NSName, ".") {
		return errors.New("--ns must be one DNS label")
	}
	addr, err := netip.ParseAddr(IP)
	if err != nil || addr.Zone() != "" || (!addr.IsGlobalUnicast() && !addr.IsLoopback()) {
		return errors.New("--ip must be a unicast IPv4 or IPv6 address")
	}
	IP = addr.Unmap().String()
	if err := validateNameservers(); err != nil {
		return err
	}
	if TLSMode != "acme" && TLSMode != "local" {
		return errors.New("--tls-mode must be acme or local")
	}
	if DataDir == "" {
		return errors.New("--data-dir cannot be empty")
	}
	if UpstreamPort < 1 || UpstreamPort > 65535 {
		return errors.New("--upstream-port must be between 1 and 65535")
	}
	if ACMEDNSTimeout < time.Second || ACMEDNSTimeout > 10*time.Minute {
		return errors.New("--acme-dns-timeout must be between 1s and 10m")
	}
	for name, value := range map[string]string{"dns-listen": DNSListen, "https-listen": HTTPSListen, "api-listen": APIListen} {
		if name == "api-listen" && value == "" {
			continue
		}
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return fmt.Errorf("invalid --%s: %w", name, err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid --%s port", name)
		}
		if host != "" && net.ParseIP(host) == nil {
			return fmt.Errorf("--%s must bind a literal IP address", name)
		}
		if name == "api-listen" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
			return errors.New("management API must bind to a loopback address; use an SSH tunnel for remote access")
		}
	}
	if ACMEEmail != "" {
		if a, err := mail.ParseAddress(ACMEEmail); err != nil || a.Address != ACMEEmail {
			return errors.New("invalid --acme-email")
		}
	}
	u, err := url.Parse(ACMEDirectory)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("--acme-directory must be an HTTPS URL")
	}
	allowedNetworks = nil
	if AllowedCIDRs != "" {
		for _, value := range strings.Split(AllowedCIDRs, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil || p.Addr().Is4In6() {
				return fmt.Errorf("invalid allowed CIDR %q", value)
			}
			allowedNetworks = append(allowedNetworks, p.Masked())
		}
	}
	if IssueHostname != "" {
		name, err := ValidateHostname(IssueHostname)
		if err != nil {
			return err
		}
		IssueHostname = name
	}
	return nil
}

var specialNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func TargetAllowed(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() || blacklist.IsBlocked(addr.String()) {
		return false
	}
	if len(allowedNetworks) > 0 {
		for _, p := range allowedNetworks {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	if addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr) {
		return false
	}
	for _, p := range specialNetworks {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

func ValidateHostname(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !validDNSName(host) {
		return "", errors.New("invalid DNS hostname")
	}
	ip, err := resolver.ParseHost(host, Domain)
	if err != nil {
		return "", err
	}
	if !TargetAllowed(ip) {
		return "", fmt.Errorf("backend %s is not allowed; configure --allowed-cidrs for private networks", ip)
	}
	return host, nil
}
