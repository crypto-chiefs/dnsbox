# Upgrading to v0.5.2

Back up each node's configuration, executable, and complete persistent certificate directory before upgrading. The old installer normally stored the executable under `~/.dnsbox` and certificate/key pairs under `/var/lib/dnsbox/certs`. Keep each node's backup private and separate.

v0.5.0 removed unauthenticated certificate sharing and automatic peer discovery and supported one authoritative instance per zone. v0.5.2 adds explicit nameserver lists and authenticated replication of temporary DNS-01 TXT values. It does not restore certificate or private-key sharing.

## Required decisions

- **Own your DNS zone.** Set a delegated domain you control in ACME mode, or a private zone in local mode. Old instructions implying that arbitrary self-hosted instances can issue certificates under `dnsbox.io` were incorrect.
- **Choose a data directory.** To retain existing `/var/lib/dnsbox/certs/*.crt` and `*.key`, set `DNSBOX_DATA_DIR=/var/lib/dnsbox` and grant the service account access. Do not accidentally switch to a new data directory. The new installer uses `~/.dnsbox/data` for new installations.
- **Normalize legacy settings.** Set `DNSBOX_DEBUG` explicitly to `true` or `false`; an empty value is invalid. The installer preserves an existing `dnsbox.env`, so edit that file before upgrading instead of expecting installer arguments to replace its contents.
- **Choose allowed backends.** Public addresses are allowed by default. Set `DNSBOX_ALLOWED_CIDRS` to restrict public backends or enable private networks explicitly. A nonempty list replaces the public default.
- **Choose one node or an explicit cluster.** With no nameserver list, DNSBox publishes only its own NS. For three nodes, configure the same `DNSBOX_NAMESERVERS` list and authenticated TXT replication on every node before resuming ACME issuance.
- **Review custom DNS records.** Deployment-specific records are no longer compiled into releases. Supply a records file explicitly when needed.

## Check existing certificates before replacing the daemon

Inventory the hostnames, validity periods, full certificate chains, and matching private keys on every node. A browser that has cached an intermediate can hide an incomplete server chain; test with a client that validates the supplied chain.

A legacy `.crt` containing only a leaf certificate cannot be adopted as a complete chain. Restore the authentic issuing intermediate certificates from the CA's official chain material, verify the leaf, hostname, and chain against trusted roots, then store the leaf followed by its intermediates in the existing `certs/<hostname>.crt`. Preserve the matching `.key`. For example, with separately prepared leaf and intermediate files:

```bash
openssl verify -purpose sslserver -verify_hostname HOSTNAME \
  -untrusted intermediates.pem leaf.pem
```

Replace `HOSTNAME` with the real certificate hostname and use a trusted CA store. Do not append unrelated certificates or disable verification. If a verified chain cannot be restored and reissuance is blocked or rate-limited, postpone that node's cutover until a usable chain is available. Upgrading the executable does not repair a missing chain by itself.

Complete, still-valid legacy Let's Encrypt production certificates can be imported into the managed cache for scheduled renewal. Local mode and ACME staging use separate stores and must not reuse production data. Running `--issue=<hostname>` validates or renews the selected certificate and refreshes its exports; it can contact the CA and is not a read-only inspection. Stop the process using that data directory before running the one-shot command. In a cluster, keep the other nodes running and reachable for TXT replication.

## Migrate a three-node zone

1. Prepare v0.5.2 binaries and configuration on all three nodes. Preserve each existing data directory and service permissions. Use the same zone, backend policy, and custom records everywhere. Assign each node its own `--ns` and advertised `--ip`.
2. Configure the same static roster on all nodes, for example `DNSBOX_NAMESERVERS='ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12'`. Replace these example IPs with the actual advertised addresses. Each node's local name and IP must match its entry. Check the parent delegation, glue, and any custom NS address overrides against that roster.
3. Create a dedicated cluster CA and a separate certificate/key for each node. Each certificate must contain the node's peer IP in its SAN and allow both server and client authentication. Keep the CA private key offline and restrict access to node credentials.
4. Set `DNSBOX_CLUSTER_FILE` on every node. Its JSON must contain the cluster listener, CA/certificate/key paths, and explicit HTTPS IP-and-port URLs for both other nodes. Allow the cluster port only between those peers. See the [complete example](../README.md#multiple-dns-nodes-and-acme).
5. Run `dnsboxd --check-config` with each node's real settings before changing its service. This checks the cluster JSON and credentials without creating the data directory or opening listeners. It does not prove public DNS reachability, peer connectivity, or that every legacy certificate has a valid chain.
6. Coordinate the cutover so automatic issuance and renewal do not rely on a mixture of legacy and new nodes. Legacy nodes cannot participate in authenticated TXT replication. Resume issuance only after all three updated nodes are reachable and their checks pass; retain the saved configuration and executable for rollback.
7. Query every advertised server over UDP and TCP 53. Confirm identical apex NS and SOA answers, correct addresses for all three NS names, and the intended per-node proxy address for encoded hostnames. Test authenticated TXT publication and removal across all three nodes, then test a controlled ACME request and trusted HTTPS forwarding.

All configured peers must accept a challenge before ACME validation proceeds. If one peer is unavailable or fails authentication, issuance fails rather than proceeding with an incomplete TXT set. Multiple simultaneous values at one challenge name are retained independently, and cleanup removes only its own value. Existing HTTPS certificates remain local to each node; the cluster does not synchronize certificate stores or local-mode CAs. DNS zone transfers remain unsupported.

## Replace fixed apex addresses with ALIAS when appropriate

If an external hosting provider owns the apex destination, configure its hostname in the custom records file rather than copying its current IPs:

```text
apps.example.com ALIAS landing.example.net.
```

Replace the example names, configure the hosting provider for your apex domain and HTTPS, and pass the file with `--records-file`. ALIAS is only valid at the zone apex, must target an external name, and cannot coexist with A, AAAA, or CNAME at that name. TXT and MX records may coexist. DNSBox resolves the target before becoming ready and refreshes it in the background. Initial resolution failure stops startup; an unrefreshed cache expires after one hour and A/AAAA queries then return SERVFAIL. No external lookup occurs while handling a DNS query.

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

Review [configuration](configuration.md) and [deployment examples](deployment.md), then test one hostname and backend before opening the updated service to clients.

If an older publicly accessible installation exposed private keys through the legacy sharing endpoint, treat those keys as potentially compromised and replace the affected certificates and keys. Do not reuse them merely to preserve continuity.
