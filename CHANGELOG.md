# Changelog

## v0.5.2 — 2026-10-24

- Explicit nameserver rosters with validated local identity, consistent NS/glue records, and a shared deterministic SOA primary across nodes.
- Dedicated-CA mutual TLS replication of temporary ACME DNS-01 TXT values to explicitly configured peers; simultaneous values and exact-value cleanup preserve other orders. Certificates and private keys remain local.
- Apex ALIAS records with initial resolution, background refresh, bounded cache lifetime, and SERVFAIL when no usable cached address is available.
- Expanded migration guidance for preserving legacy production certificates and restoring missing intermediates before cutover.
- Real three-process integration coverage for DNS, authenticated TXT fanout, peer rejection, and Linux SIGTERM/listener cleanup; configuration validation checks that avoid data or listener side effects.
- Updated all twelve README translations, three-node migration instructions, and installer release pin to v0.5.2.

## v0.5.1 — 2026-10-24

- Full README documentation in all twelve supported languages.
- Restored navigation between translations.
- Release installer pinned to v0.5.1.

## v0.5.0 — 2026-10-24

A reliability and security overhaul with explicit support for private deployments.

### Added

- Offline local TLS mode with a persistent CA and exportable hostname certificates.
- Private backend CIDR allowlists, configurable listeners/data paths, and validated CLI/environment configuration.
- One-shot certificate issuance for services that manage their own TLS.
- Regression coverage for DNS, certificates, routing, and installer workflows; CI runs before release publication.

### Fixed

- Inconsistent IPv4/IPv6 hostname parsing and authoritative DNS response behavior.
- ACME certificate lifecycle, persistent account credentials, full-chain storage, and concurrent issuance.
- HTTP/WebSocket forwarding, backend policy enforcement, and server shutdown/error handling.
- Unsafe installer downloads, systemd/manual startup handling, and destructive uninstall behavior.

### Compatibility changes

- Removed unauthenticated certificate sharing and automatic peer discovery. Single-instance zones are supported.
- Management API is loopback-only and mutations require a configured token.
- Private targets require an explicit CIDR allowlist; out-of-zone DNS requests are refused.
- Deployment-specific embedded DNS records and synthetic fallback records are removed.
- Corrected documentation: DNSBox certificates identify hostnames, self-hosting needs control of its DNS zone, and DNS-01 does not require inbound port 80.

Read [migration notes](doc/migration-v0.5.md) before upgrading.
