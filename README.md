# DNSBox — self-hosted DNS and HTTPS for IP-based hostnames

[Русский](doc/README.ru.md) · [Deployment and private networks](doc/deployment.md) · [Configuration](doc/configuration.md) · [Upgrade notes](doc/migration-v0.5.md)

[Español](doc/README.es.md) · [Deutsch](doc/README.de.md) · [Français](doc/README.fr.md) · [中文](doc/README.zh.md) · [हिन्दी](doc/README.hi.md) · [Português](doc/README.pt.md) · [Türkçe](doc/README.tr.md) · [Bahasa Indonesia](doc/README.id.md) · [Tiếng Việt](doc/README.vi.md) · [한국어](doc/README.ko.md)

DNSBox combines an authoritative DNS server with an HTTPS reverse proxy. A hostname such as `192-168-1-50.home.arpa` identifies a backend IP. DNS answers point to **the DNSBox proxy**, which terminates TLS and forwards HTTP to that backend. It supports dotted/dashed IPv4, dashed IPv6, WebSocket upgrades, and persistent certificates.

Two TLS modes are available:

- **`acme`**: certificates for hostnames in a domain you control, using ACME DNS-01 (Let's Encrypt by default). Your authoritative DNS must be publicly reachable.
- **`local`**: a persistent local CA for private networks, without public DNS, Internet access, or port forwarding. Clients must trust the generated CA.

Certificates cover DNS hostnames, not bare IP addresses. Running the software does not grant control of `dnsbox.io`. The availability or configuration of the public `dnsbox.io` service is independent of this repository.

## Private network quick start

Example: DNSBox VM `192.168.1.2`, HTTP application `192.168.1.50:80`, private zone `home.arpa`.

Download the appropriate [release archive](https://github.com/crypto-chiefs/dnsbox/releases), verify it against `checksums.txt`, and run:

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

The process needs write access to the data directory and permission to bind these ports. Configure your LAN resolver to forward **the `home.arpa` zone** to `192.168.1.2`; DNSBox does not provide general recursive DNS.

On the first certificate request, DNSBox creates `/var/lib/dnsbox/ca/root.crt` and its private key. Copy **only `root.crt`** securely to clients and install it in their trusted CA store. For a single command, test with:

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

You can create the CA and a leaf before starting the service with the same configuration plus `--issue=192-168-1-50.home.arpa`. In local mode this writes the certificate and exits without opening listeners. See the [private deployment guide](doc/deployment.md).

## Installation

Linux and macOS installer (pinned to the release):

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.2/scripts/install.sh \
  -o install-dnsbox.sh
# Review the script, then:
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

The installer verifies the archive's SHA-256 checksum, installs into `~/.dnsbox`, and uses `~/.dnsbox/data` for persistent data on a new installation. It creates a systemd service only when systemd is running. Use `--no-systemd` for manual startup, including Calculate Linux/OpenRC:

```bash
~/.dnsbox/run-dnsbox
```

The generated `~/.dnsbox/dnsbox.env` stores configuration and is preserved on upgrades. Re-running the installer upgrades binaries; edit the existing environment file to change settings. Neither installer nor uninstaller changes your system resolver or deletes system logs. On Windows, extract the archive and run `dnsboxd.exe` with the same flags.

## Public certificates and NAT

For ACME mode, delegate a domain or subdomain **you control** to your DNSBox authoritative server. Supply public glue/address records for its nameserver as necessary. Forward **both UDP and TCP port 53** to DNSBox. Allow outbound HTTPS for ACME.

DNS-01 does **not** need incoming port 80. Port 443 only needs to be reachable by clients using the HTTPS proxy. The HTTP backend can remain private: allow its network with `--allowed-cidrs`. A completely isolated network must use local TLS mode instead.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Replace example names and addresses with your own. `--ip` is the address clients use to reach DNSBox, not the backend address. An IPv4 proxy returns A records; an IPv6 proxy returns AAAA records, regardless of the backend's IP family.

## Multiple DNS nodes and ACME

Use the same static `--nameservers` list on every node. Each label must be unique and each address must be a literal unicast IP; the local `--ns` and `--ip` must match one entry. All nodes publish the same NS set, peer addresses, and SOA primary. Without this option, DNSBox publishes only its own nameserver. Keep parent delegation, glue, and any custom NS address overrides consistent.

For ACME with multiple authoritative nodes, configure `--cluster-file` on each node to replicate temporary DNS-01 TXT values. Use the same zone, backend policy, and custom records on all nodes. Example for the first node:

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12 \
  --cluster-file=/etc/dnsbox/cluster.json --data-dir=/var/lib/dnsbox
```

`cluster.json` for that node:

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "cluster-node.crt",
  "private_key": "cluster-node.key",
  "ca_certificate": "cluster-ca.crt",
  "peers": ["https://203.0.113.11:8443", "https://203.0.113.12:8443"]
}
```

Each node lists every other node as an explicit HTTPS IP-and-port URL. Restrict the cluster port to those peers. Use a dedicated cluster CA and a separate certificate/key for each node; the certificate needs that node's IP in its SAN and both server and client authentication usages. Paths are relative to the JSON file. Protect the CA and TLS files, and keep the CA private key offline. Mutual TLS authenticates peers; only temporary TXT values are replicated, never HTTPS certificates, private keys, or the local-mode CA. `DNSBOX_NAMESERVERS` and `DNSBOX_CLUSTER_FILE` are the corresponding environment variables.

## Apex ALIAS records

To point the zone apex at an external hosting name, put this in the file selected by `--records-file`:

```text
apps.example.com ALIAS landing.example.net.
```

Configure that hosting provider to serve your apex domain and HTTPS. DNSBox resolves the target before DNS becomes ready, refreshes it in the background, and answers from cached A/AAAA records without a lookup in the query path. An initial lookup failure stops startup; a cache older than one hour yields SERVFAIL for A/AAAA. ALIAS is allowed only at the apex, must target a name outside the zone, and cannot coexist with A, AAAA, or CNAME there. NS, SOA, TXT, MX, and IP-based proxy hostnames remain available. Static nameserver lists, cluster TXT replication, and ALIAS require v0.5.2 or later.

## Security and compatibility

By default only public backend addresses are allowed. An explicit `--allowed-cidrs` list restricts access to those networks, enabling private deployments. Keep a private deployment bound to LAN interfaces and behind your firewall.

The management API defaults to `127.0.0.1:8080`. Record mutations require a configured bearer token, and an empty `--api-listen=` disables it. The old unauthenticated certificate-sharing endpoints have been removed. Each node keeps its own certificate store.

Certificates and private keys persist under the data directory. Back up that directory securely. The `certs/<hostname>.crt` and `.key` files can be used by another service, such as ocserv, but DNSBox's HTTP reverse proxy is not an OpenConnect/DTLS proxy. See [certificate export instructions](doc/deployment.md#certificates-for-ocserv-or-another-service).

Read the [v0.5 migration notes](doc/migration-v0.5.md) before upgrading from v0.4.

## Development

Use the Go version declared in [go.mod](go.mod).

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

Release CI runs the checks before publishing Linux, macOS, and Windows archives for amd64 and arm64. [MIT license](LICENSE).
