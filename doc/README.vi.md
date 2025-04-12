# DNSBox — HTTPS và Let's Encrypt cho bất kỳ địa chỉ IP nào

[🇬🇧 English](../README.md) | [🇷🇺 Русский](/doc/README.ru.md) | [🇪🇸 Español](/doc/README.es.md) | [🇩🇪 Deutsch](/doc/README.de.md) | [🇫🇷 Français](/doc/README.fr.md) | [🇨🇳 中文](/doc/README.zh.md) | [🇮🇳 हिंदी](/doc/README.hi.md) | [🇧🇷 Português](/doc/README.pt.md) | [🇹🇷 Türkçe](/doc/README.tr.md) | [🇮🇩 Bahasa Indonesia](/doc/README.id.md) | [🇻🇳 Tiếng Việt](/doc/README.vi.md) | [🇰🇷 한국어](/doc/README.ko.md)

[![Release](https://img.shields.io/github/v/release/crypto-chiefs/dnsbox)](https://github.com/crypto-chiefs/dnsbox/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/crypto-chiefs/dnsbox)](../go.mod)

**DNSBox** là một máy chủ DNS mã nguồn mở cho phép cấp chứng chỉ SSL miễn phí (Let's Encrypt) cho bất kỳ địa chỉ IP công khai nào (IPv4 và IPv6) mà không cần sở hữu tên miền. Truy cập máy chủ, API hoặc thiết bị IoT của bạn trực tiếp qua IP với HTTPS.

---

## 🔍 Tính năng

- 🔐 **Chứng chỉ SSL miễn phí** từ Let's Encrypt cho địa chỉ IP
- 🌐 **Hỗ trợ IPv4 và IPv6**
- ⚡ **Truy cập HTTPS tức thì** mà không cần cấu hình DNS
- 🔄 **Tự động gia hạn chứng chỉ**
- 💡 **Hoạt động mà không cần tên miền** — sử dụng subdomain `*.dnsbox.io`
- 🧩 **Tương thích với WebSocket, API, CI/CD**
- ⚙️ **Cài đặt dễ dàng** bằng shell script
- 📦 Ít phụ thuộc, chỉ một file nhị phân, khởi động không cần cấu hình

---

## 📦 Cài đặt

```bash
bash <(curl -sSL https://raw.githubusercontent.com/crypto-chiefs/dnsbox/main/scripts/install.sh) --ip=167.172.5.205 --domain=dnsbox.io --ns=ns3
```

Tham số:
- `--ip` — địa chỉ IP công khai của bạn (bắt buộc)
- `--domain` — tên miền gốc liên kết với NS (ví dụ: `dnsbox.io`)
- `--ns` — subdomain cho máy chủ tên (ví dụ: `ns3`)
- `--force-resolv` — vô hiệu hóa systemd-resolved và đặt thành 8.8.8.8
- `--debug` — bật chế độ gỡ lỗi chi tiết

---

## 🌐 Cách hoạt động

1. DNSBox khởi chạy máy chủ tên phục vụ bản ghi A/AAAA và TXT động.
2. Bạn nhận được subdomain như `167.172.5.205.dnsbox.io`.
3. Let's Encrypt xác minh bản ghi TXT `_acme-challenge` và cấp chứng chỉ.
4. DNSBox lưu trữ, tự động gia hạn và phân phối chứng chỉ SSL.

---

## 🛠 Ví dụ sử dụng

Sau khi cài đặt, bạn có thể kết nối với máy chủ của mình qua HTTPS:

```bash
curl https://167.172.5.205.dnsbox.io
```

Hoặc kiểm tra kết nối SSL bằng OpenSSL:

```bash
openssl s_client -connect 167.172.5.205:443 -servername 167.172.5.205.dnsbox.io
```

---

## ⚙️ Công nghệ bên trong

- Ngôn ngữ: Go
- Thư viện DNS: [miekg/dns](https://github.com/miekg/dns)
- TLS: thư viện chuẩn `crypto/tls`
- ACME client: tích hợp sẵn, không cần certbot
- Tất cả logic được xử lý trong bộ nhớ

---

## 🧪 Trường hợp sử dụng

- 🔧 Hạ tầng DevOps không cần tên miền
- 📡 Thiết bị IoT có IP công khai
- 🧪 Môi trường thử nghiệm và staging
- 🚀 Triển khai API nhanh không cần DNS
- 🔐 Dịch vụ VPN hoặc proxy yêu cầu HTTPS

---

## 🔒 Bảo mật

Tất cả yêu cầu xác thực Let's Encrypt chỉ được xử lý trong thời gian xác minh IP hợp lệ. Khóa riêng TLS được lưu tại `/var/lib/dnsbox/certs`.

---

## 🗺 Thay thế cho sslip.io và nip.io

Khác với các dịch vụ hiện tại:
- DNSBox là **giải pháp mã nguồn mở tự lưu trữ**
- Bạn có thể triển khai `*.yourdomain.tld` của riêng mình
- Hỗ trợ **IPv6**, ACME và chứng chỉ **không cần API bên thứ ba**

---

## 📜 Giấy phép

Dự án được cấp phép theo giấy phép MIT. Tự do sử dụng, fork, mở rộng.

---

## 🔗 Liên kết hữu ích

- 🌍 Website dự án: https://dnsbox.io/
- 📦 Trình cài đặt: [install.sh](https://github.com/crypto-chiefs/dnsbox/blob/main/scripts/install.sh)
- 📖 Tài liệu: đang cập nhật

---

⭐ Nếu bạn thấy dự án hữu ích, hãy ⭐ nó trên GitHub!
