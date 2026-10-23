# Configuration

Flags override environment variables. Run `dnsboxd --help` for the current complete list. `dnsboxd --version` needs no configuration. `--check-config` validates settings without starting network listeners.

| Flag | Environment variable | Default / meaning |
| --- | --- | --- |
| `--domain` | `DNSBOX_DOMAIN` | Required zone under your control; `home.arpa` is suitable for local mode |
| `--ip` | `DNSBOX_IP` | Required advertised proxy address, reachable by clients |
| `--ns` | `DNSBOX_NS_NAME` | `ns1`, nameserver label in the zone |
| `--nameservers` | `DNSBOX_NAMESERVERS` | Optional comma-separated `label=IP` roster; empty publishes the local NS only |
| `--cluster-file` | `DNSBOX_CLUSTER_FILE` | Optional JSON file for authenticated DNS-01 TXT replication |
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

## Authoritative nameservers

Set the same `--nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12` roster on every node, replacing the example IPs with your addresses. Labels must be unique DNS labels and addresses must be literal unicast IPs. The local `--ns` and `--ip` must match one entry. Private and loopback addresses are accepted for private deployments.

Each node answers all roster names, publishes the same apex NS set, and chooses the first hostname in sorted order as the SOA primary. The encoded backend hostnames still resolve to that node's own proxy address. Custom A/AAAA records for a nameserver override its configured address and glue; keep those records and the parent delegation consistent on every node.

## Authenticated challenge replication

For ACME with multiple authoritative nodes, provide `--cluster-file` on each node. The JSON fields are `listen`, `certificate`, `private_key`, `ca_certificate`, and `peers`; see the [complete example](../README.md#multiple-dns-nodes-and-acme). Relative credential paths are resolved from the JSON file's directory.

Use a dedicated cluster CA and a separate node certificate/key with that node's reachable peer IP in the SAN and both server and client authentication usages. Each node explicitly lists every other node as an `https://IP:port` URL; IPv6 addresses need brackets. DNS hostnames, paths, query strings, duplicate peers, and the node's own endpoint are rejected. At most eight peers are supported. The listener accepts a literal IP and port, including a wildcard bind. Restrict its port to the configured peers and protect all credential files; keep the CA private key offline.

Mutual TLS is required. Only temporary DNS-01 TXT values are replicated, and issuance proceeds only after every configured peer acknowledges the value. Cleanup deletes that exact value. HTTPS certificate files, private keys, local-mode CAs, and custom DNS record files are not copied. A static NS roster alone does not replicate challenges. `--check-config` validates JSON and credentials without opening listeners, but does not test peer connectivity.

## Custom DNS records

Use a file containing `name type value` records, then pass its path with `--records-file`. See [the sample](../internal/customdns/custom_domain.example.txt) for supported examples. Records must belong to the configured zone. Restart DNSBox after changing the file.

Do not replace the zone apex or nameserver with a CNAME. DNSBox owns its SOA and nameserver records. Custom DNS records are not routes for the HTTPS proxy.

Supported types are A, AAAA, CNAME, MX, TXT, and apex-only ALIAS. An ALIAS target must be a hostname outside the zone and cannot coexist with A, AAAA, or CNAME at the apex. Configure the target hosting service for your apex domain and HTTPS. For example:

```text
apps.example.com ALIAS landing.example.net.
```

The target is resolved before DNS is ready and refreshed in the background every minute. Queries use cached A/AAAA answers. Initial resolution failure stops startup; after one hour without a successful refresh, A/AAAA queries return SERVFAIL. Other apex record types and encoded proxy hostnames are unaffected. Static nameserver rosters, cluster replication, and ALIAS require v0.5.2 or later.

## ACME testing

To test a public deployment before using production rate limits:

```bash
--acme-directory=https://acme-staging-v02.api.letsencrypt.org/directory
```

Staging certificates are not trusted by normal browsers. Use a separate data directory for staging and production, and keep local-CA data separate from ACME data.
