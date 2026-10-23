# Configuration

Flags override environment variables. Run `dnsboxd --help` for the current complete list. `dnsboxd --version` needs no configuration. `--check-config` validates settings without starting network listeners.

| Flag | Environment variable | Default / meaning |
| --- | --- | --- |
| `--domain` | `DNSBOX_DOMAIN` | Required zone under your control; `home.arpa` is suitable for local mode |
| `--ip` | `DNSBOX_IP` | Required advertised proxy address, reachable by clients |
| `--ns` | `DNSBOX_NS_NAME` | `ns1`, nameserver label in the zone |
| `--tls-mode` | `DNSBOX_TLS_MODE` | `acme` or `local` |
| `--allowed-cidrs` | `DNSBOX_ALLOWED_CIDRS` | Empty: public backends only. Otherwise restrict to comma-separated CIDRs |
| `--dns-listen` | `DNSBOX_DNS_LISTEN` | `:53`, both UDP and TCP |
| `--https-listen` | `DNSBOX_HTTPS_LISTEN` | `:443` |
| `--api-listen` | `DNSBOX_API_LISTEN` | `127.0.0.1:8080`; loopback only, empty disables |
| `--api-token` | `DNSBOX_API_TOKEN` | No default; API mutations disabled without a token |
| `--upstream-port` | `DNSBOX_UPSTREAM_PORT` | `80`, HTTP backend port |
| `--data-dir` | `DNSBOX_DATA_DIR` | Direct binary: `/var/lib/dnsbox` on Linux; user configuration directory on other platforms |
| `--acme-email` | `DNSBOX_ACME_EMAIL` | Optional ACME account contact |
| `--acme-directory` | `DNSBOX_ACME_DIRECTORY` | Let's Encrypt production directory |
| `--acme-dns-timeout` | `DNSBOX_ACME_DNS_TIMEOUT` | `2m`, DNS propagation timeout (between `1s` and `10m`) |
| `--records-file` | `DNSBOX_RECORDS_FILE` | Optional custom DNS records file |
| `--debug` | `DNSBOX_DEBUG` | `false` |
| `--issue=HOSTNAME` | — | Obtain/export a certificate and exit; DNS listener in ACME mode only, no HTTPS listener |

The installer chooses `~/.dnsbox/data` on a new installation instead of the direct binary's default. Protect the data directory: it contains the ACME account key, server private keys, and (in local mode) the CA private key.

Use bracketed IPv6 for listeners, for example `--dns-listen=[fd00::2]:53`. Both `192.168.1.50.home.arpa` and `192-168-1-50.home.arpa` encode IPv4; `fd00--50.home.arpa` encodes `fd00::50`. Names outside the configured zone are refused. A certificate hostname must encode an allowed backend IP; arbitrary custom record names do not automatically become proxy routes.

An explicit CIDR allowlist replaces public-by-default access. For example, `--allowed-cidrs=192.168.1.0/24,fd00::/64` serves only those networks. The abuse blacklist still applies; unspecified and multicast addresses remain disallowed.

For development without privileged ports:

```bash
./dnsboxd --domain=home.arpa --ip=127.0.0.1 \
  --tls-mode=local --allowed-cidrs=127.0.0.1/32 \
  --dns-listen=127.0.0.1:1053 --https-listen=127.0.0.1:8443 \
  --upstream-port=8081 --data-dir=./dnsbox-data
```

Start a backend on port 8081. Your client URL must then include `:8443`; ordinary DNS does not carry a browser's HTTPS port. For ACME, high DNS ports work only if public port 53 is forwarded to them.

## Custom DNS records

Use a file containing `name type value` records, then pass its path with `--records-file`. See [the sample](../internal/customdns/custom_domain.example.txt) for supported examples. Records must belong to the configured zone. Restart DNSBox after changing the file.

Do not replace the zone apex or nameserver with a CNAME. DNSBox owns its SOA and nameserver records. Custom DNS records are not routes for the HTTPS proxy.

## ACME testing

To test a public deployment before using production rate limits:

```bash
--acme-directory=https://acme-staging-v02.api.letsencrypt.org/directory
```

Staging certificates are not trusted by normal browsers. Use a separate data directory for staging and production, and keep local-CA data separate from ACME data.
