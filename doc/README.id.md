# DNSBox — DNS dan HTTPS yang dihosting sendiri untuk nama host berbasis IP

[English](../README.md) · [Русский](README.ru.md) · [Penerapan dan jaringan privat](deployment.md) · [Konfigurasi](configuration.md) · [Catatan peningkatan versi](migration-v0.5.md)

DNSBox menggabungkan server DNS otoritatif dengan proksi balik HTTPS. Nama host seperti `192-168-1-50.home.arpa` menunjukkan alamat IP sebuah backend. Jawaban DNS mengarah ke **proksi DNSBox**, yang menangani terminasi TLS dan meneruskan HTTP ke backend tersebut. DNSBox mendukung IPv4 dengan pemisah titik atau tanda hubung, IPv6 dengan tanda hubung, peningkatan koneksi ke WebSocket, serta penyimpanan sertifikat secara persisten.

Tersedia dua mode TLS:

- **`acme`**: sertifikat untuk nama host dalam domain yang Anda kendalikan, menggunakan ACME DNS-01 dengan Let's Encrypt sebagai pilihan bawaan. DNS otoritatif Anda harus dapat diakses dari Internet publik.
- **`local`**: otoritas sertifikat (CA) lokal yang disimpan secara persisten untuk jaringan privat, tanpa DNS publik, akses Internet, atau penerusan port. Klien harus dikonfigurasi untuk memercayai CA yang dihasilkan.

Sertifikat berlaku untuk nama host DNS, bukan alamat IP tanpa nama domain. Menjalankan perangkat lunak ini tidak memberi Anda kendali atas `dnsbox.io`. Ketersediaan dan konfigurasi layanan publik `dnsbox.io` terpisah dari repositori ini.

## Mulai cepat di jaringan privat

Contoh: VM DNSBox berada di `192.168.1.2`, aplikasi HTTP di `192.168.1.50:80`, dan zona privatnya adalah `home.arpa`.

Unduh [arsip rilis](https://github.com/crypto-chiefs/dnsbox/releases) yang sesuai, verifikasi menggunakan `checksums.txt`, lalu jalankan:

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

Proses memerlukan izin menulis ke direktori data dan izin untuk menggunakan port tersebut. Konfigurasikan resolver DNS di LAN agar meneruskan kueri untuk **zona `home.arpa`** ke `192.168.1.2`; DNSBox tidak menyediakan layanan DNS rekursif umum.

Pada permintaan sertifikat pertama, DNSBox membuat `/var/lib/dnsbox/ca/root.crt` beserta kunci privatnya. Salin **hanya `root.crt`** secara aman ke klien dan pasang di penyimpanan CA tepercaya mereka. Untuk mempercayai sertifikat hanya pada satu perintah, uji dengan:

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

Anda dapat membuat CA dan sertifikat server sebelum menjalankan layanan dengan konfigurasi yang sama ditambah `--issue=192-168-1-50.home.arpa`. Dalam mode lokal, perintah ini menulis sertifikat lalu keluar tanpa membuka port untuk menerima koneksi. Lihat [panduan penerapan privat](deployment.md).

## Instalasi

Penginstal Linux dan macOS berikut menggunakan versi rilis tertentu:

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.1/scripts/install.sh \
  -o install-dnsbox.sh
# Periksa isi skrip, lalu jalankan:
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

Penginstal memverifikasi checksum SHA-256 arsip, memasang program ke `~/.dnsbox`, dan menggunakan `~/.dnsbox/data` untuk data persisten pada instalasi baru. Layanan systemd hanya dibuat jika systemd sedang berjalan. Gunakan `--no-systemd` untuk menjalankan layanan secara manual, termasuk pada Calculate Linux/OpenRC:

```bash
~/.dnsbox/run-dnsbox
```

File `~/.dnsbox/dnsbox.env` yang dihasilkan menyimpan konfigurasi dan dipertahankan saat peningkatan versi. Menjalankan ulang penginstal akan memperbarui berkas biner; sunting file lingkungan yang sudah ada untuk mengubah pengaturan. Penginstal maupun penghapus instalasi tidak mengubah resolver sistem atau menghapus log sistem. Di Windows, ekstrak arsip lalu jalankan `dnsboxd.exe` dengan opsi yang sama.

## Sertifikat publik dan NAT

Untuk mode ACME, delegasikan domain atau subdomain **yang Anda kendalikan** ke server DNS otoritatif DNSBox Anda. Sediakan catatan glue atau alamat publik untuk server nama tersebut sesuai kebutuhan. Teruskan **port 53 untuk UDP dan TCP** ke DNSBox. Izinkan koneksi HTTPS keluar untuk ACME.

DNS-01 **tidak** memerlukan akses masuk ke port 80. Port 443 hanya perlu dapat dijangkau oleh klien yang menggunakan proksi HTTPS. Backend HTTP dapat tetap berada di jaringan privat: izinkan jaringannya melalui `--allowed-cidrs`. Jaringan yang sepenuhnya terisolasi harus menggunakan mode TLS lokal.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Ganti nama dan alamat contoh dengan milik Anda. `--ip` adalah alamat yang digunakan klien untuk mengakses DNSBox, bukan alamat backend. Proksi IPv4 mengembalikan catatan A; proksi IPv6 mengembalikan catatan AAAA, terlepas dari versi IP yang digunakan backend.

## Keamanan dan kompatibilitas

Secara bawaan, hanya alamat backend publik yang diizinkan. Daftar `--allowed-cidrs` yang ditentukan secara eksplisit membatasi akses ke jaringan yang tercantum, sehingga memungkinkan penerapan privat. Ikat penerapan privat ke antarmuka LAN dan lindungi dengan firewall Anda.

API pengelolaan menggunakan `127.0.0.1:8080` secara bawaan. Perubahan catatan memerlukan token bearer yang sudah dikonfigurasi, dan nilai kosong `--api-listen=` menonaktifkan API. Endpoint berbagi sertifikat lama yang tidak memerlukan autentikasi telah dihapus. v0.5 mendukung **satu instans DNSBox per zona**; sinkronisasi sertifikat dan tantangan validasi antarnode tidak didukung.

Sertifikat dan kunci privat disimpan secara persisten di direktori data. Cadangkan direktori tersebut dengan aman. File `certs/<hostname>.crt` dan `.key` dapat digunakan oleh layanan lain, seperti ocserv, tetapi proksi balik HTTP DNSBox bukan proksi OpenConnect/DTLS. Lihat [petunjuk ekspor sertifikat](deployment.md#certificates-for-ocserv-or-another-service).

Baca [catatan migrasi v0.5](migration-v0.5.md) sebelum meningkatkan versi dari v0.4.

## Pengembangan

Gunakan versi Go yang ditentukan dalam [go.mod](../go.mod).

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

CI rilis menjalankan pemeriksaan tersebut sebelum menerbitkan arsip Linux, macOS, dan Windows untuk amd64 serta arm64. Proyek ini menggunakan [lisensi MIT](../LICENSE).
