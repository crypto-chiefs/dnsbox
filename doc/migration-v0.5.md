# Upgrading from v0.4 to v0.5

Back up your configuration and persistent certificate directory before upgrading. The old installer normally stored the executable under `~/.dnsbox` and certificate/key pairs under `/var/lib/dnsbox/certs`.

## Required decisions

- **Own your DNS zone.** Set a delegated domain you control in ACME mode, or a private zone in local mode. Old instructions implying that arbitrary self-hosted instances can issue certificates under `dnsbox.io` were incorrect.
- **Choose a data directory.** To retain existing `/var/lib/dnsbox/certs/*.crt` and `*.key`, set `DNSBOX_DATA_DIR=/var/lib/dnsbox` and grant the service account access. Do not accidentally switch to a new data directory. The new installer uses `~/.dnsbox/data` for new installations.
- **Choose allowed backends.** Public addresses are allowed by default. Set `DNSBOX_ALLOWED_CIDRS` to restrict public backends or enable private networks explicitly. A nonempty list replaces the public default.
- **Choose a single authoritative instance.** Legacy peer discovery and certificate-sharing are removed; they were unreliable and lacked authentication. Independent DNSBox nodes no longer exchange TXT records or keys.
- **Review custom DNS records.** Deployment-specific records are no longer compiled into releases. Supply a records file explicitly when needed.

## Changes that may affect deployment

- The management API moves from public port 80 to loopback port 8080. Mutations need a bearer token; empty API listener configuration disables it. Certificate-sharing endpoints are gone.
- No port 80 forwarding is needed for ACME DNS-01. Public validation still requires correct authoritative DNS over both UDP and TCP 53.
- DNS answers are limited to the configured zone; fabricated fallback CNAME/MX records are removed.
- IPv4 and IPv6 backends share one hostname parser. Answers use the IP family of the configured **proxy** address.
- The local TLS mode creates its own persistent CA. It is not publicly trusted. Install its root certificate on clients and keep CA private keys secure.
- Use one running process per data directory. Keep local mode, ACME staging, and ACME production in separate directories.
- The installer rejects `--force-resolv`; it no longer rewrites `/etc/resolv.conf` or disables resolver services.
- The uninstaller removes known executables and its matching service only. Configuration, certificates, and system logs remain intact.
- GoReleaser now uses the v2 configuration schema. Release archives retain the `dnsbox-<os>-<arch>.tar.gz` names and include checksums.

Run `dnsboxd --check-config` with the new settings, then test one hostname and backend before opening the service to clients. Before starting the daemon, run `--issue=<hostname>` for each legacy certificate you want to retain or renew: this validates/reissues it as needed and creates the v0.5 cache used by scheduled renewal. Legacy certificates lacking their intermediate chain require reissuance. Review [configuration](configuration.md) and [deployment examples](deployment.md).

If an older publicly accessible installation exposed private keys through the legacy sharing endpoint, treat those keys as potentially compromised and replace the affected certificates and keys. Do not reuse them merely to preserve continuity.
