# DNSBox

DNSBox menggabungkan server DNS otoritatif dengan reverse proxy HTTPS. Nama seperti `192-168-1-50.home.arpa` menyandikan IP backend; DNS mengarah ke proxy DNSBox.

- `--tls-mode=local`: jaringan privat tanpa Internet atau penerusan port. Klien harus memercayai CA lokal.
- `--tls-mode=acme`: sertifikat untuk nama dalam zona DNS yang Anda kendalikan; memerlukan DNS publik melalui UDP dan TCP 53. DNS-01 tidak memerlukan port 80 masuk.
- Backend privat memerlukan daftar `--allowed-cidrs` yang eksplisit.
- Sertifikat mencakup nama DNS, bukan IP tanpa domain. Instalasi tidak memberikan kendali atas `dnsbox.io`.

Petunjuk lama telah diganti untuk v0.5. Dokumentasi lengkap terbaru tersedia dalam bahasa Inggris:

[Panduan](../README.md) · [Jaringan privat dan NAT](deployment.md) · [Konfigurasi](configuration.md) · [Migrasi](migration-v0.5.md)