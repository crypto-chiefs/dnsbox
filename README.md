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
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.1/scripts/install.sh \
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

## Security and compatibility

By default only public backend addresses are allowed. An explicit `--allowed-cidrs` list restricts access to those networks, enabling private deployments. Keep a private deployment bound to LAN interfaces and behind your firewall.

The management API defaults to `127.0.0.1:8080`. Record mutations require a configured bearer token, and an empty `--api-listen=` disables it. The old unauthenticated certificate-sharing endpoints have been removed. v0.5 supports a **single DNSBox instance per zone**; multi-node certificate/challenge synchronization is not supported.

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
