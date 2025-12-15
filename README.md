# DNSBox — HTTPS and Let's Encrypt for Any IP Address

[🇬🇧 English](README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](go.mod)

**DNSBox** is an open-source DNS server that allows you to issue free SSL certificates (Let's Encrypt) for any public IP address (IPv4 and IPv6) without owning a domain. Get HTTPS access to a server, API, or IoT device directly by IP.

---

## 🔍 Features

- 🔐 **Free SSL certificates** from Let's Encrypt for IP addresses
- 🌐 **Supports IPv4 and IPv6**
- ⚡ **Instant HTTPS access** without DNS configuration
- 🔄 **Automatic certificate renewal**
- 💡 **Works without a domain** — use `*.dnsbox.io` subdomains
- 🧩 **Compatible with WebSocket, APIs, and CI/CD pipelines**
- ⚙️ **Lightweight installer** via shell script
- 📦 Minimal dependencies, single binary, zero-config launch

---

## 📦 Installation

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Parameters:
- `--ip` — your public IP address (required)
- `--domain` — the root domain bound to the NS (e.g., `dnsbox.io`)
- `--ns` — nameserver subdomain (e.g., `ns3`)
- `--force-resolv` — disables systemd-resolved and sets 8.8.8.8
- `--debug` — enables verbose output

---

## 🌐 How It Works

1. DNSBox launches a nameserver that serves A/AAAA and TXT records on the fly.
2. You get a subdomain like `167.172.5.205.dnsbox.io`.
3. Let's Encrypt checks for a `_acme-challenge` TXT record and issues a certificate.
4. DNSBox automatically stores, renews, and serves the SSL certificate.

---

## 🛠 Example Usage

After installation, you can connect to your server over HTTPS:

```bash
curl https://167.172.5.205.dnsbox.io
```

Or test the SSL via OpenSSL:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Under the Hood

- Language: Go
- DNS Library: [miekg/dns](https://github.com/miekg/dns)
- TLS: standard `crypto/tls`
- ACME Client: built-in ACME support (no certbot)
- On-the-fly logic: all DNS queries and challenges are handled in memory

---

## 🧪 Use Cases

- 🔧 DevOps infrastructure without domains
- 📡 IoT devices with public IPs
- 🧪 Lab/staging environments
- 🚀 Fast API deployment without DNS
- 🔐 VPN/Proxy services requiring HTTPS

---

## 🔒 Security

All Let's Encrypt challenge requests are served only during valid IP validation. TLS private keys are stored in `/var/lib/dnsbox/certs`.

---

## 🗺 Alternative to sslip.io and nip.io

Unlike existing services:
- DNSBox is a **self-hosted open-source solution**
- Deploy your own `*.yourdomain.tld`
- Supports **IPv6**, ACME, and certificates **without third-party APIs**

---

## 📜 License

This project is licensed under the MIT License. Use it freely, fork it, extend it.

---

## 🧪 Testing

DNSBox includes comprehensive unit tests. See [TESTING.md](TESTING.md) for details.

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage
```

## 🔗 Useful Links

- 🌍 Project website: https://dnsbox.io/
- 📦 Installer: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Documentation: in progress
- 🧪 Testing Guide: [TESTING.md](TESTING.md)

---

⭐ If you find this project useful, please star it on GitHub!
