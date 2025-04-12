# DNSBox — HTTPS dan Let's Encrypt untuk Alamat IP Apa Pun

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** adalah server DNS open-source yang memungkinkan Anda mendapatkan sertifikat SSL gratis (Let's Encrypt) untuk alamat IP publik apa pun (IPv4 dan IPv6) tanpa perlu memiliki nama domain. Akses server, API, atau perangkat IoT Anda secara langsung melalui HTTPS berdasarkan IP.

---

## 🔍 Fitur

- 🔐 **Sertifikat SSL gratis** dari Let's Encrypt untuk alamat IP
- 🌐 **Dukungan IPv4 dan IPv6**
- ⚡ **Akses HTTPS instan** tanpa konfigurasi DNS
- 🔄 **Pembaruan otomatis sertifikat**
- 💡 **Berfungsi tanpa domain** — gunakan subdomain `*.dnsbox.io`
- 🧩 **Kompatibel dengan WebSocket, API, dan skenario CI/CD**
- ⚙️ **Installer ringan** melalui skrip shell
- 📦 Ketergantungan minimal, satu file biner, tanpa konfigurasi

---

## 📦 Instalasi

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Parameter:
- `--ip` — alamat IP publik Anda (wajib)
- `--domain` — domain utama yang ditautkan ke NS (contoh: `dnsbox.io`)
- `--ns` — subdomain untuk nameserver (contoh: `ns3`)
- `--force-resolv` — menonaktifkan systemd-resolved dan mengatur 8.8.8.8
- `--debug` — aktifkan mode verbose

---

## 🌐 Cara Kerja

1. DNSBox menjalankan nameserver yang melayani catatan A/AAAA dan TXT secara dinamis.
2. Anda mendapatkan subdomain seperti `167.172.5.205.dnsbox.io`.
3. Let's Encrypt memverifikasi catatan TXT `_acme-challenge` dan mengeluarkan sertifikat.
4. DNSBox secara otomatis menyimpan, memperbarui, dan menyajikan sertifikat SSL.

---

## 🛠 Contoh Penggunaan

Setelah instalasi, Anda dapat mengakses server Anda melalui HTTPS:

```bash
curl https://167.172.5.205.dnsbox.io
```

Atau uji koneksi SSL menggunakan OpenSSL:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Teknologi Inti

- Bahasa: Go
- Pustaka DNS: [miekg/dns](https://github.com/miekg/dns)
- TLS: pustaka standar `crypto/tls`
- Klien ACME: dukungan ACME bawaan (tanpa certbot)
- Semua logika berjalan di memori

---

## 🧪 Kasus Penggunaan

- 🔧 Infrastruktur DevOps tanpa domain
- 📡 Perangkat IoT dengan IP publik
- 🧪 Lingkungan pengujian dan staging
- 🚀 Deploy API cepat tanpa pengaturan DNS
- 🔐 Layanan VPN atau proxy yang memerlukan HTTPS

---

## 🔒 Keamanan

Semua permintaan verifikasi Let's Encrypt hanya dilayani saat validasi IP aktif. Kunci privat TLS disimpan di `/var/lib/dnsbox/certs`.

---

## 🗺 Alternatif untuk sslip.io dan nip.io

Berbeda dengan layanan lain:
- DNSBox adalah **solusi open-source self-hosted**
- Anda dapat menerapkan infrastruktur `*.yourdomain.tld` sendiri
- Mendukung **IPv6**, ACME, dan sertifikat **tanpa API pihak ketiga**

---

## 📜 Lisensi

Proyek ini dilisensikan di bawah MIT. Gunakan secara bebas, fork, dan kembangkan.

---

## 🔗 Tautan Berguna

- 🌍 Situs web: https://dnsbox.io/
- 📦 Installer: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Dokumentasi: sedang dikembangkan

---

⭐ Jika proyek ini bermanfaat bagi Anda, mohon beri bintang di GitHub!
