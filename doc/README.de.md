# DNSBox — HTTPS und Let's Encrypt für jede IP-Adresse

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** ist ein Open-Source-DNS-Server, der es ermöglicht, kostenlose SSL-Zertifikate (Let's Encrypt) für beliebige öffentliche IP-Adressen (IPv4 und IPv6) auszustellen – ganz ohne Domainbesitz. Erhalten Sie HTTPS-Zugriff auf Ihren Server, Ihre API oder Ihr IoT-Gerät direkt über die IP-Adresse.

---

## 🔍 Funktionen

- 🔐 **Kostenlose SSL-Zertifikate** von Let's Encrypt für IP-Adressen
- 🌐 **Unterstützung für IPv4 und IPv6**
- ⚡ **Sofortiger HTTPS-Zugriff** ohne DNS-Konfiguration
- 🔄 **Automatische Zertifikatserneuerung**
- 💡 **Funktioniert ohne Domain** – verwenden Sie `*.dnsbox.io` Subdomains
- 🧩 **Kompatibel mit WebSocket, APIs und CI/CD-Pipelines**
- ⚙️ **Leichtgewichtiger Installer** über Shell-Skript
- 📦 Minimale Abhängigkeiten, Einzel-Binary, keine Konfiguration nötig

---

## 📦 Installation

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Parameter:
- `--ip` – Ihre öffentliche IP-Adresse (erforderlich)
- `--domain` – Root-Domain, die mit dem NS verbunden ist (z. B. `dnsbox.io`)
- `--ns` – Subdomain des Nameservers (z. B. `ns3`)
- `--force-resolv` – deaktiviert systemd-resolved und setzt 8.8.8.8
- `--debug` – ausführlicher Modus

---

## 🌐 Funktionsweise

1. DNSBox startet einen Nameserver, der dynamisch A/AAAA- und TXT-Einträge liefert.
2. Sie erhalten eine Subdomain wie `167.172.5.205.dnsbox.io`.
3. Let's Encrypt überprüft den `_acme-challenge` TXT-Eintrag und stellt das Zertifikat aus.
4. DNSBox speichert, erneuert und stellt das SSL-Zertifikat automatisch bereit.

---

## 🛠 Beispielverwendung

Nach der Installation können Sie sich per HTTPS mit Ihrem Server verbinden:

```bash
curl https://167.172.5.205.dnsbox.io
```

Oder das Zertifikat mit OpenSSL testen:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Interna

- Sprache: Go
- DNS-Bibliothek: [miekg/dns](https://github.com/miekg/dns)
- TLS: Standard `crypto/tls`
- ACME-Client: integrierte ACME-Unterstützung (kein certbot)
- Dynamische Logik: alle DNS-Anfragen und Challenges im Speicher verarbeitet

---

## 🧪 Anwendungsfälle

- 🔧 DevOps-Infrastruktur ohne Domains
- 📡 IoT-Geräte mit öffentlicher IP
- 🧪 Test- und Staging-Umgebungen
- 🚀 Schnelle API-Bereitstellung ohne DNS
- 🔐 VPN-/Proxy-Dienste, die HTTPS erfordern

---

## 🔒 Sicherheit

Alle Let's Encrypt Challenge-Anfragen werden nur während der IP-Validierung bedient. TLS-Schlüssel werden unter `/var/lib/dnsbox/certs` gespeichert.

---

## 🗺 Alternative zu sslip.io und nip.io

Im Gegensatz zu bestehenden Diensten:
- DNSBox ist eine **selbst gehostete Open-Source-Lösung**
- Sie können Ihre eigene `*.yourdomain.tld` Infrastruktur betreiben
- Unterstützt **IPv6**, ACME und Zertifikate **ohne Drittanbieter-APIs**

---

## 📜 Lizenz

Dieses Projekt ist unter der MIT-Lizenz veröffentlicht. Frei verwendbar, forkbar und erweiterbar.

---

## 🔗 Nützliche Links

- 🌍 Projektwebsite: https://dnsbox.io/
- 📦 Installer: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Dokumentation: in Arbeit

---

⭐ Wenn Ihnen dieses Projekt gefällt, freuen wir uns über einen ⭐ bei GitHub.
